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

/* $Id: get-job-attributes.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_get_job_attributes(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_job_t j = NULL;
	papi_attribute_t **operational = NULL;
	papi_attribute_t **job_attributes = NULL;

	char **req_attrs = NULL;
	char *queue = NULL;
	int id = -1;

	/* Get operational attributes from the request */
	(void) papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &operational);

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
	 * the operational-attributes-group should contain:
	 *	requested-attributes
	 */
	get_string_list(operational, "requested-attributes", &req_attrs);

	if ((status = papiJobQuery(svc, queue, id, req_attrs, &j)) != PAPI_OK) {
		ipp_set_status(response, status, "query job: %s",
				ipp_svc_status_mesg(svc, status));
		papiJobFree(j); /* we shouldn't have a job, but just in case */
		return (status);
	}

	/* add the job attributes to the response in a job-attributes-group */
	if (j != NULL) {
		papi_to_ipp_job_group(response, request, PAPI_ATTR_REPLACE, j);
		papiJobFree(j);
	}

	return (status);
}
