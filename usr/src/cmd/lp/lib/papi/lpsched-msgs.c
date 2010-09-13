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

#include <stdio.h>
#include <stdarg.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


/* lpsched include files */
#include "lp.h"
#include "msgs.h"
#include "printers.h"
#include "class.h"

#include <papi_impl.h>


/*
 * Format and send message to lpsched (die if any errors occur)
 */
/*VARARGS1*/
int
snd_msg(service_t *svc, int type, ...)
{
	int rc = -1;
	va_list	ap;

	if (svc == NULL)
		return (-1);

	/* fill the message buffer */
	va_start(ap, type);
	rc = _putmessage(svc->msgbuf, type, ap);
	va_end(ap);
	if (rc < 0) {
		detailed_error(svc,
		    gettext("unable to build message for scheduler: %s"),
		    strerror(errno));
		return (rc);
	}

	/* write the message */
	while (((rc = mwrite(svc->md, svc->msgbuf)) < 0) && (errno == EINTR)) {
	}

	if (rc < 0)
		detailed_error(svc,
		    gettext("unable to send message to scheduler: %s"),
		    strerror(errno));
	return (rc);
}

/*
 * Receive message from lpsched (die if any errors occur)
 */
int
rcv_msg(service_t *svc, int type, ...)
{
	int rc = -1;

	if (svc == NULL)
		return (-1);

	/* read the message */
	while (((rc = mread(svc->md, svc->msgbuf, svc->msgbuf_size)) < 0) &&
	    (errno == EINTR)) {
	}

	if (rc < 0)
		detailed_error(svc,
		    gettext("unable to read message from scheduler: %s"),
		    strerror(errno));
	else {
		va_list ap;

		va_start(ap, type);
		rc = _getmessage(svc->msgbuf, type, ap);
		va_end(ap);

		if (rc < 0)
			detailed_error(svc,
			gettext("unable to parse message from scheduler: %s"),
			    strerror(errno));
	}

	return (rc);
}

papi_status_t
lpsched_status_to_papi_status(int status)
{
	switch (status) {
	case MNOMEM:
		return (PAPI_TEMPORARY_ERROR);
	case MNOFILTER:
		return (PAPI_DOCUMENT_FORMAT_ERROR);
	case MNOOPEN:
		return (PAPI_DOCUMENT_ACCESS_ERROR);
	case MERRDEST:
	case MDENYDEST:
		return (PAPI_NOT_ACCEPTING);
	case MNOMEDIA:
		return (PAPI_PRINT_SUPPORT_FILE_NOT_FOUND);
	case MDENYMEDIA:
	case MNOPERM:
		return (PAPI_NOT_AUTHORIZED);
	case MUNKNOWN:
	case MNODEST:
	case MNOINFO:
		return (PAPI_NOT_FOUND);
	case MTRANSMITERR:
		return (PAPI_SERVICE_UNAVAILABLE);
	case M2LATE:
		return (PAPI_GONE);
	case MBUSY:
		return (PAPI_PRINTER_BUSY);
	case MOK:
	case MOKMORE:
		return (PAPI_OK);
	}

	return (PAPI_INTERNAL_ERROR);
}

char *
lpsched_status_string(short status)
{
		switch (status) {
	case MNOMEM:
		return (gettext("lpsched: out of memory"));
	case MNOFILTER:
		return (gettext("No filter available to convert job"));
	case MNOOPEN:
		return (gettext("lpsched: could not open request"));
	case MERRDEST:
		return (gettext("queue disabled"));
	case MDENYDEST:
		return (gettext("destination denied request"));
	case MNOMEDIA:
		return (gettext("unknown form specified in job"));
	case MDENYMEDIA:
		return (gettext("access denied to form specified in job"));
	case MUNKNOWN:
		return (gettext("no such resource"));
	case MNODEST:
		return (gettext("unknown destination"));
	case MNOPERM:
		return (gettext("permission denied"));
	case MNOINFO:
		return (gettext("no information available"));
	case MTRANSMITERR:
		return (gettext("failure to communicate with lpsched"));
	default: {
		static char result[16];

		snprintf(result, sizeof (result), gettext("status: %d"),
		    status);
		return (result);
		}
	}
}

papi_status_t
lpsched_alloc_files(papi_service_t svc, int number, char **prefix)
{
	papi_status_t result = PAPI_OK;
	short status = MOK;

	if ((svc == NULL) || (prefix == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((snd_msg(svc, S_ALLOC_FILES, number) < 0) ||
	    (rcv_msg(svc, R_ALLOC_FILES, &status, prefix) < 0))
		status = MTRANSMITERR;

	if (status != MOK) {
		detailed_error(svc,
		gettext("failed to allocate %d file(s) for request: %s"),
		    number, lpsched_status_string(status));
		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
lpsched_commit_job(papi_service_t svc, char *job, char **tmp)
/* job is host/req-id */
{
	papi_status_t result = PAPI_OK;
	short status = MOK;
	long bits;

	if ((svc == NULL) || (job == NULL) || (tmp == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((snd_msg(svc, S_PRINT_REQUEST, job) < 0) ||
	    (rcv_msg(svc, R_PRINT_REQUEST, &status, tmp, &bits) < 0))
		status = MTRANSMITERR;

	if (status != MOK) {
		detailed_error(svc, gettext("failed to commit job (%s): %s"),
			job, lpsched_status_string(status));
		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
lpsched_start_change(papi_service_t svc, char *printer, int32_t job_id,
		char **tmp)
{
	papi_status_t result = PAPI_OK;
	short status = MOK;
	char req[BUFSIZ];
	char *dest;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, job_id);
	snprintf(req, sizeof (req), "%s-%d", dest, job_id);
	free(dest);

	if ((snd_msg(svc, S_START_CHANGE_REQUEST, req) < 0) ||
	    (rcv_msg(svc, R_START_CHANGE_REQUEST, &status, tmp) < 0))
		status = MTRANSMITERR;

	if (status != MOK) {
		detailed_error(svc,
		gettext("failed to initiate change for job (%s-%d): %s"),
		    printer,
		    job_id, lpsched_status_string(status));
		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
lpsched_end_change(papi_service_t svc, char *printer, int32_t job_id)
{
	papi_status_t result = PAPI_OK;
	short status = MOK;
	long bits;
	char req[BUFSIZ];
	char *dest;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, job_id);
	snprintf(req, sizeof (req), "%s-%d", dest, job_id);
	free(dest);

	if ((snd_msg(svc, S_END_CHANGE_REQUEST, req) < 0) ||
	    (rcv_msg(svc, R_END_CHANGE_REQUEST, &status, &bits) < 0))
		status = MTRANSMITERR;

	if (status != MOK) {
		detailed_error(svc,
		gettext("failed to commit change for job (%s-%d): %s"), printer,
		    job_id, lpsched_status_string(status));
		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
lpsched_accept_printer(papi_service_t svc, char *printer)
{
	papi_status_t result = PAPI_OK;
	short	status = MOK;
	char	*req_id;
	char *dest;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, -1);
	if ((snd_msg(svc, S_ACCEPT_DEST, dest) < 0) ||
	    (rcv_msg(svc, R_ACCEPT_DEST, &status, &req_id) < 0))
		status = MTRANSMITERR;
	free(dest);

	if ((status != MOK) && (status != MERRDEST)) {
		detailed_error(svc, "%s: %s", printer,
		    lpsched_status_string(status));
	}
	result = lpsched_status_to_papi_status(status);

	return (result);
}

papi_status_t
lpsched_reject_printer(papi_service_t svc, char *printer, char *message)
{
	papi_status_t result = PAPI_OK;
	short	 status = MOK;
	char	*req_id;
	char *dest;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (message == NULL)
		message = "stopped by user";

	dest = printer_name_from_uri_id(printer, -1);
	if ((snd_msg(svc, S_REJECT_DEST, dest, message, 0) < 0) ||
	    (rcv_msg(svc, R_REJECT_DEST, &status, &req_id) < 0))
		status = MTRANSMITERR;
	free(dest);

	if ((status != MOK) && (status != MERRDEST)) {
		detailed_error(svc, "%s: %s", printer,
		    lpsched_status_string(status));
	}
	result = lpsched_status_to_papi_status(status);

	return (result);
}

papi_status_t
lpsched_enable_printer(papi_service_t svc, char *printer)
{
	papi_status_t result = PAPI_OK;
	short	 status = MOK;
	char	*req_id;
	char *dest;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, -1);
	if ((snd_msg(svc, S_ENABLE_DEST, dest) < 0) ||
	    (rcv_msg(svc, R_ENABLE_DEST, &status, &req_id) < 0))
		status = MTRANSMITERR;
	free(dest);

	if ((status != MOK) && (status != MERRDEST)) {
		detailed_error(svc, "%s: %s", printer,
		    lpsched_status_string(status));
	}
	result = lpsched_status_to_papi_status(status);

	return (result);
}

papi_status_t
lpsched_disable_printer(papi_service_t svc, char *printer, char *message)
{
	papi_status_t result = PAPI_OK;
	short	 status = MOK;
	char	*req_id;
	char *dest;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (message == NULL)
		message = "stopped by user";

	dest = printer_name_from_uri_id(printer, -1);
	if ((snd_msg(svc, S_DISABLE_DEST, dest, message, 0) < 0) ||
	    (rcv_msg(svc, R_DISABLE_DEST, &status, &req_id) < 0))
		status = MTRANSMITERR;
	free(dest);

	if ((status != MOK) && (status != MERRDEST)) {
		detailed_error(svc, "%s: %s", printer,
		    lpsched_status_string(status));
	}
	result = lpsched_status_to_papi_status(status);

	return (result);
}

papi_status_t
lpsched_load_unload_dest(papi_service_t handle, char *dest, int type)
{
	service_t *svc = handle;
	papi_status_t result;
	short status = MOK;

	/* tell the scheduler it's going */
	if (snd_msg(svc, type, dest, "", "") < 0)
		return (PAPI_SERVICE_UNAVAILABLE);

	switch (type) {
	case S_LOAD_PRINTER:
		type = R_LOAD_PRINTER;
		break;
	case S_UNLOAD_PRINTER:
		type = R_UNLOAD_PRINTER;
		break;
	case S_LOAD_CLASS:
		type = R_LOAD_CLASS;
		break;
	case S_UNLOAD_CLASS:
		type = R_UNLOAD_CLASS;
	}

	if (rcv_msg(svc, type, &status) < 0)
		return (PAPI_SERVICE_UNAVAILABLE);

	result = lpsched_status_to_papi_status(status);

	return (result);
}

papi_status_t
lpsched_remove_class(papi_service_t handle, char *dest)
{
	papi_status_t result;

	/* tell the scheduler it's going */
	result = lpsched_load_unload_dest(handle, dest, S_UNLOAD_CLASS);

	if (result == PAPI_OK) {
		/* remove the scheduler config files */
		if (delclass(dest) == -1)
			result = PAPI_SERVICE_UNAVAILABLE;
	}

	return (result);
}

static void
remove_from_class(papi_service_t handle, char *dest, CLASS *cls)
{
	if (dellist(&cls->members, dest) == 0) {
		if (cls->members != NULL) {
			if (putclass(cls->name, cls) == 0)
				(void) lpsched_load_unload_dest(handle,
				    cls->name, S_LOAD_CLASS);
		} else
			(void) lpsched_remove_class(handle, cls->name);
	}
}

papi_status_t
lpsched_remove_printer(papi_service_t handle, char *dest)
{

	papi_status_t result;

	/* tell the scheduler it's going */
	result = lpsched_load_unload_dest(handle, dest, S_UNLOAD_PRINTER);

	if (result == PAPI_OK) {
		CLASS *cls;
		char *dflt;

		/* remove the scheduler config files */
		if (delprinter(dest) == -1)
			return (PAPI_SERVICE_UNAVAILABLE);

		/* remove from any classes */
		while ((cls = getclass(NAME_ALL)) != NULL) {
			if (searchlist(dest, cls->members) != 0)
				remove_from_class(handle, dest, cls);
			freeclass(cls);
		}

		/* reset the default if it needs to be done */
		if (((dflt = getdefault()) != NULL) &&
		    (strcmp(dflt, dest) == 0))
			putdefault(NAME_NONE);
	}

	return (result);
}

papi_status_t
lpsched_add_modify_class(papi_service_t handle, char *dest,
		papi_attribute_t **attributes)
{
	papi_status_t result;
	void *iter = NULL;
	char **members = NULL;
	char *member;

	/*
	 * The only attribute that we can modify for a class is the set of
	 * members.  Anything else will be ignored.
	 */
	for (result = papiAttributeListGetString(attributes, &iter,
	    "member-names", &member);
	    result == PAPI_OK;
	    result = papiAttributeListGetString(attributes, &iter,
	    NULL, &member))
		addlist(&members, member);

	if (members != NULL) {
		/* modify the configuration file */
		CLASS class;

		memset(&class, 0, sizeof (class));
		class.name = dest;
		class.members = members;

		if (putclass(dest, &class) == -1) {
			if ((errno == EPERM) || (errno == EACCES))
				result = PAPI_NOT_AUTHORIZED;
			else
				result = PAPI_NOT_POSSIBLE;
		} else
			result = PAPI_OK;

		freelist(members);
	} else
		result = PAPI_ATTRIBUTES;

	/* tell the scheduler about the changes */
	if (result == PAPI_OK)
		result = lpsched_load_unload_dest(handle, dest, S_LOAD_CLASS);

	return (result);
}

papi_status_t
lpsched_add_printer(papi_service_t handle, char *dest,
		papi_attribute_t **attributes)
{
	PRINTER *p;
	papi_status_t result = PAPI_TEMPORARY_ERROR;

	if ((p = calloc(1, sizeof (*p))) != NULL) {
		p->name = strdup(dest);
		p->banner = BAN_ALWAYS;
		p->interface = strdup("/usr/lib/lp/model/uri");
		p->fault_alert.shcmd = strdup("mail");

		attributes_to_printer(attributes, p);

		if (putprinter(dest, p) == -1) {
			if ((errno == EPERM) || (errno == EACCES))
				result = PAPI_NOT_AUTHORIZED;
			else
				result = PAPI_NOT_POSSIBLE;
		} else
			result = PAPI_OK;

		freeprinter(p);
	}

	/* tell the scheduler about the changes */
	if (result == PAPI_OK)
		result = lpsched_load_unload_dest(handle, dest, S_LOAD_PRINTER);

	return (result);
}

papi_status_t
lpsched_add_modify_printer(papi_service_t handle, char *dest,
		papi_attribute_t **attributes, int type)
{
	PRINTER *p;
	papi_status_t result;

	if (type == 0) {
		if ((p = calloc(1, sizeof (*p))) != NULL) {
			p->name = strdup(dest);
			p->banner = BAN_ALWAYS;
			p->interface = strdup("/usr/lib/lp/model/uri");
			p->fault_alert.shcmd = strdup("mail");
		}
	} else
		p = getprinter(dest);

	if (p != NULL) {
		attributes_to_printer(attributes, p);

		if (putprinter(dest, p) == -1) {
			if ((errno == EPERM) || (errno == EACCES))
				result = PAPI_NOT_AUTHORIZED;
			else
				result = PAPI_NOT_POSSIBLE;
		} else
			result = PAPI_OK;

		freeprinter(p);
	} else
		result = PAPI_NOT_POSSIBLE;

	/* tell the scheduler about the changes */
	if (result == PAPI_OK)
		result = lpsched_load_unload_dest(handle, dest, S_LOAD_PRINTER);

	return (result);
}
