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

/* $Id: get-printer-attributes.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_get_printer_attributes(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_printer_t p = NULL;
	papi_attribute_t **operational = NULL;
	papi_attribute_t **printer_attributes = NULL;

	char **req_attrs = NULL;
	char *doc_fmt = NULL;
	char *queue = NULL;

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
	 *	requested-attributes
	 *	document-format
	 */
	get_string_list(operational, "requested-attributes", &req_attrs);
	(void) papiAttributeListGetString(operational, NULL,
			"document-format", &doc_fmt);
	status = papiPrinterQuery(svc, queue, req_attrs, NULL, &p);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "query printer: %s",
				ipp_svc_status_mesg(svc, status));
		papiPrinterFree(p); /* we shouldn't have a printer */
		return (status);
	}

	/*
	 * add the printer attributes to the response in a
	 * printer-attributes-group
	 */
	if (p != NULL) {
		papi_to_ipp_printer_group(response, request,
					PAPI_ATTR_REPLACE, p);
		papiPrinterFree(p);
	}

	return (status);
}
