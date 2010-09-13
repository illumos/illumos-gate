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

/* $Id: cups-get-printers.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
cups_get_printers(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_printer_t *p = NULL;
	papi_attribute_t **operational = NULL;
	papi_filter_t filt;

	char **req_attrs = NULL;
	int limit = 0;

	/* Get operational attributes from the request */
	(void) papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &operational);

	/*
	 * The operational-attributes-group may contain:
	 *	limit
	 *	printer-info
	 *	printer-location
	 *	printer-type
	 *	printer-type-mask
	 *	requested-attributes
	 */

	papiAttributeListGetInteger(operational, NULL, "limit", &limit);

	get_string_list(operational, "requested-attributes", &req_attrs);

	/* only ask for the classes */
	filt.type = PAPI_FILTER_BITMASK;
	filt.filter.bitmask.mask = ~PAPI_PRINTER_CLASS;
	filt.filter.bitmask.value = PAPI_PRINTER_LOCAL | PAPI_PRINTER_REMOTE;

	/* query the print service for printers information */
	status = papiPrintersList(svc, req_attrs, &filt, &p);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "query printers: %s",
				ipp_svc_status_mesg(svc, status));
		papiPrinterListFree(p); /* we shouldn't have any printers */
		return (status);
	}

	if (p != NULL) {
		int i;

		for (i = 0; p[i] != NULL; i++)
			papi_to_ipp_printer_group(response, request,
					PAPI_ATTR_APPEND, p[i]);
		papiPrinterListFree(p);
	}

	return (status);
}
