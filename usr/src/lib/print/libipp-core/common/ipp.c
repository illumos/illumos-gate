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

/* $Id: ipp.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <papi.h>
#include "ipp.h"

/*
 * IPP requests/responses are represented as attribute lists.  An IPP request
 * attribute list will contain header information attributes:
 *	version-major (int)
 *	version-minor (int)
 *	request-id (int)
 *	operation-id (int)
 * It will also contain 1 or more attribute groups (collections)
 *	operational-attribute-group
 *		...
 * this routine validates that the request falls within the guidelines of
 * the protocol specification (or some other level of conformance if the
 * restrictions have been specified at the top level of the request using
 * a "conformance" attribute.
 */
papi_status_t
ipp_validate_request(papi_attribute_t **request, papi_attribute_t ***response)
{
	papi_attribute_t **attributes = NULL;
	papi_status_t result = PAPI_OK;
	char *s;

	if ((request == NULL) || (response == NULL) || (*response == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* validate the operational attributes group */
	result = papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &attributes);
	if (result != PAPI_OK) {
		ipp_set_status(response, result,
				"operational attribute group: %s",
				papiStatusString(result));
		return (result);
	}

	result = papiAttributeListGetString(attributes, NULL,
				"attributes-charset", &s);
	if (result != PAPI_OK) {
		ipp_set_status(response, result, "attributes-charset: %s",
				papiStatusString(result));
		return (result);
	}

	result = papiAttributeListGetString(attributes, NULL,
				"attributes-natural-language", &s);
	if (result != PAPI_OK) {
		ipp_set_status(response, result,
				"attributes-natural-language: %s",
				papiStatusString(result));
		return (result);
	}

	return (result);
}

/*
 * Add/Modify the statuse-code and status-message in an IPP response's
 * operational attributes group.
 */
void
ipp_set_status(papi_attribute_t ***message, papi_status_t status,
		char *format, ...)
{
	if (message == NULL)
		return;

	if (format != NULL) {
		papi_attribute_t **operational = NULL;
		papi_attribute_t **saved;
		char mesg[256];	/* status-message is type text(255) */
		va_list ap;

		(void) papiAttributeListGetCollection(*message, NULL,
					"operational-attributes-group",
					&operational);
		saved = operational;

		va_start(ap, format);
		(void) vsnprintf(mesg, sizeof (mesg), format, ap);
		va_end(ap);

		(void) papiAttributeListAddString(&operational,
				PAPI_ATTR_APPEND, "status-message", mesg);

		/*
		 * We need to check and see if adding the status-message caused
		 * the operational attributes group to be relocated in memory.
		 * If it has been, we will need to re-add the collection to
		 * the message.
		 */
		if (saved != operational)
			(void) papiAttributeListAddCollection(message,
					PAPI_ATTR_REPLACE,
					"operational-attributes-group",
					operational);
	}

	(void) papiAttributeListAddInteger(message, PAPI_ATTR_APPEND,
				"status-code", status);
}
