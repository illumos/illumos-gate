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

/* $Id: hold-job.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_hold_job(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_attribute_t **operational = NULL;

	char *message = NULL;
	char *queue = NULL;
	int id = -1;

	/* Get operational attributes from the request */
	papiAttributeListGetCollection(request, NULL,
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
	 * the operational-attributes-group may contain:
	 *	message
	 *	job-hold-until (ingored)
	 */
	(void) papiAttributeListGetString(operational, NULL,
				"message", &message);

	if ((status = papiJobHold(svc, queue, id)) != PAPI_OK) {
		ipp_set_status(response, status,
				"hold failed: %s-%d: %s",
				(queue ? queue : "(null)"), id,
				ipp_svc_status_mesg(svc, status));
	} else if (message != NULL) {	/* add unsupported attribute group */
		papi_attribute_t **unsupported = NULL;

		papiAttributeListAddValue(&unsupported, PAPI_ATTR_EXCL,
				"message", PAPI_COLLECTION, NULL);
		(void) papiAttributeListAddCollection(response,
			PAPI_ATTR_REPLACE, "unsupported-attributes-group",
			unsupported);
		papiAttributeListFree(unsupported);

		status = PAPI_OK_SUBST;
		ipp_set_status(response, status,
			"unsupported attribute in request");
	}

	return (status);
}
