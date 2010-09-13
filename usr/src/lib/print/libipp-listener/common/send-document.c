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

/* $Id: send-document.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

/*
 * When the PAPI supports papiJobCreate(), papiJobStreamAdd() and
 * papiJobClose(), this will be much cleaner and more efficient, but in the
 * meantime, we are using a private, non-standard interface to do this.
 */
papi_status_t
ipp_send_document(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response, ipp_reader_t iread, void *fd)
{
	papi_status_t status;
	papi_stream_t s = NULL;
	papi_job_t j = NULL;
	papi_attribute_t **operational = NULL;
	papi_attribute_t **job_attributes = NULL;
	char *queue = NULL;
	ssize_t rc;
	int id = -1;
	char buf[BUFSIZ];
	char last = PAPI_FALSE;
	char *keys[] = { "attributes-natural-language", "attributes-charset",
			"printer-uri", "job-id", "job-uri", "last-document",
			NULL };

	/* Get operational attributes from the request */
	(void) papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &operational);

	/*
	 * the operational-attributes-group must contain:
	 *	job-uri (or printer-uri/job-id)
	 *	last-document
	 */
	get_printer_id(operational, &queue, &id);
	if (id < 0) {
		ipp_set_status(response, PAPI_BAD_REQUEST,
				"missing job-uri or job-id");
		return (PAPI_BAD_REQUEST);
	} else if (queue == NULL) {
		ipp_set_status(response, PAPI_BAD_REQUEST,
				"missing printer-uri or job-uri");
		return (PAPI_BAD_REQUEST);
	}

	status = papiAttributeListGetBoolean(operational, NULL,
			"last-document", &last);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "last-document: %s",
				papiStatusString(status));
		return (PAPI_BAD_REQUEST);
	}

	/*
	 * the operational-attributes-group may contain:
	 *	document-name
	 *	compression
	 *	document-format
	 *	document-natural-language
	 * Simply copy the entire contents of the operational-attributes-group
	 * for the PAPI call's possible use.
	 */
	split_and_copy_attributes(keys, operational, NULL, &job_attributes);

	/* copy any job-attributes-group attributes for the PAPI call */
	if (papiAttributeListGetCollection(request, NULL,
			"job-attributes-group", &operational) == PAPI_OK)
		copy_attributes(&job_attributes, operational);

	/* create a stream to write the document data on */
	status = papiJobStreamAdd(svc, queue, id, &s);
	papiAttributeListFree(job_attributes);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "job submission: %s",
				ipp_svc_status_mesg(svc, status));
		return (status);
	}

	/* copy the document data from the IPP connection to the stream */
	while ((status == PAPI_OK) && ((rc = iread(fd, buf, sizeof (buf))) > 0))
		status = papiJobStreamWrite(svc, s, buf, rc);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "write job data: %s",
				ipp_svc_status_mesg(svc, status));
		return (status);
	}

	/* close the stream */
	status = papiJobStreamClose(svc, s, &j);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "close job stream: %s",
				ipp_svc_status_mesg(svc, status));
		papiJobFree(j); /* we shouldn't have a job, but just in case */
		return (status);
	}

	/* if it's the last document, commit the job */
	if (last == PAPI_TRUE) {
		status = papiJobCommit(svc, queue, id);
	}

	/* add the job attributes to the response in a job-attributes-group */
	if (j != NULL) {
		papi_to_ipp_job_group(response, request, PAPI_ATTR_REPLACE, j);
		papiJobFree(j);
	}

	return (status);
}
