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

/* $Id: get-jobs.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_get_jobs(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_job_t *j = NULL;
	papi_attribute_t **operational = NULL;

	char **req_attrs = NULL;
	char *queue = NULL;
	int limit = 0;
	char my_jobs = PAPI_FALSE;
	char *which;
	int type = 0;

	/* Get operational attributes from the request */
	(void) papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &operational);

	/*
	 * The operational-attributes-group must contain:
	 *	printer-uri
	 */
	get_printer_id(operational, &queue, NULL);
	if (queue == NULL) {
		ipp_set_status(response, status, "printer-uri: %s",
			papiStatusString(status));
		return (PAPI_BAD_REQUEST);
	}

	/*
	 * The operational-attributes-group may contain:
	 *	limit
	 *	requested-attributes
	 *	which-jobs
	 *	my-jobs
	 */
	(void) papiAttributeListGetString(operational, NULL,
				"which-jobs", &which);
	(void) papiAttributeListGetBoolean(operational, NULL,
				"my-jobs", &my_jobs);
	(void) papiAttributeListGetInteger(operational, NULL, "limit", &limit);
	get_string_list(operational, "requested-attributes", &req_attrs);

	status = papiPrinterListJobs(svc, queue, req_attrs, type, limit, &j);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "query jobs: %s",
				ipp_svc_status_mesg(svc, status));
		return (status);
	}

	/* add any job's attributes to the response in job-attribute-groups */
	if (j != NULL) {
		int i;

		for (i = 0; j[i] != NULL; i++)
			papi_to_ipp_job_group(response, request,
					PAPI_ATTR_APPEND, j[i]);
		papiJobListFree(j);
	}

	return (status);
}
