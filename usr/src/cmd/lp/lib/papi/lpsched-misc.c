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
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <papi_impl.h>


papi_status_t
papiAttributeListAddLPString(papi_attribute_t ***list, int flags, char *name,
		char *value)
{
	papi_status_t result = PAPI_BAD_ARGUMENT;

	if ((list != NULL) && (name != NULL) && (value != NULL) &&
	    (value[0] != '\0'))
		result = papiAttributeListAddString(list, flags, name, value);
	return (result);
}

papi_status_t
papiAttributeListAddLPStrings(papi_attribute_t ***list, int flags, char *name,
				char **values)
{
	papi_status_t result = PAPI_OK;
	int i, flgs = flags;

	if ((list == NULL) || (name == NULL) || (values == NULL))
		result = PAPI_BAD_ARGUMENT;

	for (i = 0; ((result == PAPI_OK) && (values[i] != NULL));
		i++, flgs = PAPI_ATTR_APPEND)
		result = papiAttributeListAddString(list, flgs, name,
							values[i]);

	return (result);
}

void
papiAttributeListGetLPString(papi_attribute_t **attributes, char *key,
				char **string)
{
	char *value = NULL;

	papiAttributeListGetString(attributes, NULL, key,  &value);
	if (value != NULL) {
		if (*string != NULL)
			free(*string);
		*string = strdup(value);
	}
}

void
papiAttributeListGetLPStrings(papi_attribute_t **attributes, char *key,
				char ***strings)
{
	papi_status_t status;
	char **values = NULL;
	char *value = NULL;
	void *iter = NULL;

	for (status = papiAttributeListGetString(attributes, &iter,
				key, &value);
	    status == PAPI_OK;
	    status = papiAttributeListGetString(attributes, &iter,
				NULL, &value))
		addlist(&values, value);

	if (values != NULL) {
		if (*strings != NULL)
			freelist(*strings);
		*strings = values;
	}
}

char *
printer_name_from_uri_id(char *uri, int32_t id)
{
	REQUEST *request = NULL;
	char *result = "";

	if (uri != NULL) {
		if ((result = strrchr(uri, '/')) != NULL) {
			result += 1;
		} else
			result = (char *)uri;

		if ((strcmp(result, "jobs") == 0) ||
		    (strcmp(result, "any") == 0) ||
		    (strcmp(result, "all") == 0))
			result = "";
	}

	if ((result[0] == '\0') && (id != -1)) {
		char path[32];

		snprintf(path, sizeof (path), "%d-0", id);
		if ((request = getrequest(path)) != NULL)
			result = request->destination;
	}

	result = strdup(result);

	if (request != NULL)
		freerequest(request);

	return (result);
}

/*
 * LP content type <-> MIME type conversion table. (order dependent)
 */
static struct {
	char *mime_type;
	char *lp_type;
} type_map[] = {
	{ "text/plain", "simple" },
	{ "application/octet-stream", "raw" },
	{ "application/octet-stream", "any" },
	{ "application/postscript", "postscript" },
	{ "application/postscript", "ps" },
	{ "application/x-cif", "cif" },
	{ "application/x-dvi", "dvi" },
	{ "application/x-plot", "plot" },
	{ "application/x-ditroff", "troff" },
	{ "application/x-troff", "otroff" },
	{ "application/x-pr", "pr" },
	{ "application/x-fortran", "fortran" },
	{ "application/x-raster", "raster" },
	{ NULL, NULL}
};

char *
mime_type_to_lp_type(char *mime_type)
{
	int i;

	if (mime_type == NULL)
		return ("simple");

	for (i = 0; type_map[i].mime_type != NULL; i++)
		if (strcasecmp(type_map[i].mime_type, mime_type) == 0)
			return (type_map[i].lp_type);

	return (mime_type);
}

char *
lp_type_to_mime_type(char *lp_type)
{
	int i;

	if (lp_type == NULL)
		return ("text/plain");

	for (i = 0; type_map[i].lp_type != NULL; i++)
		if (strcasecmp(type_map[i].lp_type, lp_type) == 0)
			return (type_map[i].mime_type);

	return (lp_type);
}
