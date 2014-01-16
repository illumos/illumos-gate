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

/* $Id: create-job.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_create_job(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_job_t j = NULL;
	papi_attribute_t **operational = NULL;
	papi_attribute_t **job_attributes = NULL;
	char *queue = NULL;
	char *keys[] = { "attributes-natural-language", "attributes-charset",
			"printer-uri", NULL };

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
	 *	job-name
	 *	ipp-attribute-fidelity
	 *	document-name
	 *	compression
	 *	document-format
	 *	document-natural-language
	 *	job-k-octets
	 *	job-impressions
	 *	job-media-sheets
	 * Simply copy the entire contents of the operational-attributes-group
	 * for the PAPI call's possible use.
	 */

	/* copy the pointers only, not the elements */
	split_and_copy_attributes(keys, operational, NULL, &job_attributes);

	/* copy any job-attributes-group attributes for the PAPI call */
	if (papiAttributeListGetCollection(request, NULL,
			"job-attributes-group", &operational) == PAPI_OK)
		copy_attributes(&job_attributes, operational);

	/*
	 * request job creation, using Sun extention to PAPI.  The
	 * functionality in this extension is expected to make the
	 * next revision of the PAPI.
	 */
	status = papiJobCreate(svc, queue, job_attributes, NULL, &j);
	papiAttributeListFree(job_attributes);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "job creation: %s",
				ipp_svc_status_mesg(svc, status));
		return (status);
	}

	/* add the job attributes to the response in a job-attributes-group */
	if (j != NULL) {
		papi_to_ipp_job_group(response, request, PAPI_ATTR_REPLACE, j);
		papiJobFree(j);
	}

	return (status);
}
