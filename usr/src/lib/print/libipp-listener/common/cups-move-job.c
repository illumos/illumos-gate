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

/* $Id: cups-move-job.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
cups_move_job(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_attribute_t **operational = NULL, **job = NULL;

	char *message = NULL;
	char *job_printer_uri = NULL;
	char *queue = NULL;
	char *dest = NULL;
	int id = -1;

	/* Get operational attributes from the request */
	(void) papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &operational);

	/*
	 * Get job attributes from the request
	 */
	status = papiAttributeListGetCollection(request, NULL,
				"job-attributes-group", &job);
	if (status != PAPI_OK) {
		ipp_set_status(response, status,
				"job-attributes-group: %s",
				papiStatusString(status));
		return (status);
	}

	/*
	 * the operational-attributes-group must contain:
	 *	job-uri (or printer-uri/job-id)
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

	/*
	 * the job-attributes-group must contain:
	 *	job-printer-uri
	 */
	job_printer_uri = NULL;
	(void) papiAttributeListGetString(job, NULL,
				"job-printer-uri", &job_printer_uri);
	if (job_printer_uri == NULL) {
		ipp_set_status(response, PAPI_BAD_REQUEST,
				"missing job-printer-uri");
		return (PAPI_BAD_REQUEST);
	} else
		dest = destination_from_printer_uri(job_printer_uri);

	if ((status = papiJobMove(svc, queue, id, dest)) != PAPI_OK)
		ipp_set_status(response, status,
				"move failed: %s-%d to %s: %s",
				(queue ? queue : "(null)"), id,
				(dest ? dest : "(null)"),
				ipp_svc_status_mesg(svc, status));

	return (status);
}
