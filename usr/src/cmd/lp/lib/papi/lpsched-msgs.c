/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdarg.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>


/* lpsched include files */
#include "lp.h"
#include "msgs.h"
#include "printers.h"

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
	while (((rc = mwrite(svc->md, svc->msgbuf)) < 0) && (errno == EINTR));

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
		(errno == EINTR));

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
		return (PAPI_DEVICE_ERROR);
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
		return (gettext("An error occured in submission"));
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
lpsched_start_change(papi_service_t svc, const char *printer, int32_t job_id,
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
lpsched_end_change(papi_service_t svc, const char *printer, int32_t job_id)
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
lpsched_enable_printer(papi_service_t svc, const char *printer)
{
	papi_status_t result = PAPI_OK;
	short	 status;
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
		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
lpsched_disable_printer(papi_service_t svc, const char *printer,
		const char *message)
{
	papi_status_t result = PAPI_OK;
	short	 status;
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
		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}
