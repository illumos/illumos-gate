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

/* $Id: disable-printer.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_disable_printer(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_attribute_t **operational = NULL;

	char *queue = NULL;
	char *message = NULL;

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
	 *	printer-message-from-operator
	 */
	(void) papiAttributeListGetString(operational, NULL,
				"printer-message-from-operator", &message);

	if ((status = papiPrinterDisable(svc, queue, message)) != PAPI_OK) {
		ipp_set_status(response, status, "disable failed: %s: %s",
				(queue ? queue : "(null)"),
				ipp_svc_status_mesg(svc, status));
	}

	return (status);
}
