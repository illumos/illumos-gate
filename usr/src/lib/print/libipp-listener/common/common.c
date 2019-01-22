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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <papi.h>
#include <ipp-listener.h>

char *
ipp_svc_status_mesg(papi_service_t svc, papi_status_t status)
{
	char *mesg =  papiServiceGetStatusMessage(svc);

	if (mesg == NULL)
		mesg = papiStatusString(status);

	return (mesg);
}

char *
destination_from_printer_uri(char *uri)
{
	char *result = NULL;

	if (uri != NULL)
		result = strrchr(uri, '/');

	if (result == NULL)
		result = uri;
	else
		result++;

	return (result);
}

void
get_printer_id(papi_attribute_t **attributes, char **printer, int *id)
{
	papi_status_t result;
	char *job = NULL;
	char *fodder;
	int junk;

	if (printer == NULL)
		printer = &fodder;
	if (id == NULL)
		id = &junk;

	*printer = NULL;
	*id = -1;

	result = papiAttributeListGetString(attributes, NULL, "job-uri", &job);
	if (result != PAPI_OK) {
		result = papiAttributeListGetString(attributes, NULL,
		    "printer-uri", printer);
		if (result == PAPI_OK)
			papiAttributeListGetInteger(attributes, NULL,
			    "job-id", id);
	} else {
		*printer = job;
		if ((job = strrchr(*printer, '/')) != NULL) {
			*job = '\0';
			*id = atoi(++job);
		}
	}
}

void
get_string_list(papi_attribute_t **attributes, char *name, char ***values)
{
	papi_status_t result;

	void *iterator = NULL;
	char *value = NULL;

	for (result = papiAttributeListGetString(attributes, &iterator,
	    name, &value);
	    result == PAPI_OK;
	    result = papiAttributeListGetString(attributes, &iterator,
	    NULL, &value))
		list_append(values, value);
}

void
add_default_attributes(papi_attribute_t ***attributes)
{

	(void) papiAttributeListAddString(attributes, PAPI_ATTR_APPEND,
	    "ipp-versions-supported", "1.0");
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_APPEND,
	    "ipp-versions-supported", "1.1");
	(void) papiAttributeListAddBoolean(attributes, PAPI_ATTR_EXCL,
	    "multiple-document-jobs-supported", 0);
	/*
	 * Should be able to ask the web server if it supports SSL or TLS, but
	 * for now, we pick only "none"
	 */
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_EXCL,
	    "uri-security-supported", "none");

	/*
	 * For now, we only "none".  As we support more authentication methods,
	 * we will need to add the associated uri for each.  Valid values would
	 * be:
	 *	"none", "requesting-user-name", "basic", "digest", "certificate"
	 * See RFC2911 page 127 for more information.
	 */
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_EXCL,
	    "uri-authentication-supported", "requesting-user-name");
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_EXCL,
	    "uri-security-supported", "none");
	/* printer-uri-supported is added in the service based attributes */

	(void) papiAttributeListAddInteger(attributes, PAPI_ATTR_EXCL,
	    "multiple-operation-time-out", 60);

	/* I18N related */
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_EXCL,
	    "charset-configured", "utf-8");
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_EXCL,
	    "charset-supported", "utf-8");
	(void) papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
	    "natural-language-configured", "en-us");
}

static void
massage_printer_attributes_group(papi_attribute_t **group, char *printer_uri)
{
	if (papiAttributeListFind(group, "printer-uri-supported") != NULL)
		papiAttributeListAddString(&group, PAPI_ATTR_REPLACE,
		    "printer-uri-supported", printer_uri);
}

static void
massage_job_attributes_group(papi_attribute_t **group, char *printer_uri)
{
	if (papiAttributeListFind(group, "job-printer-uri") != NULL)
		papiAttributeListAddString(&group, PAPI_ATTR_REPLACE,
		    "job-printer-uri", printer_uri);

	if (papiAttributeListFind(group, "job-printer-uri") != NULL) {
		char buf[BUFSIZ];
		int32_t id = -1;

		papiAttributeListGetInteger(group, NULL, "job-id", &id);
		snprintf(buf, sizeof (buf), "%s/%d", printer_uri, id);
		papiAttributeListAddString(&group, PAPI_ATTR_REPLACE,
		    "job-uri", buf);
	}
}

/*
 * This function will replace the job/printer URIs with the requested
 * uri because the print service may return a URI that isn't IPP based.
 */
void
massage_response(papi_attribute_t **request, papi_attribute_t **response)
{
	papi_status_t status;
	papi_attribute_t **group = NULL;
	void *iter = NULL;
	char *host = "localhost";
	char *path = "/printers/";
	int port = 631;
	char buf[BUFSIZ];

	(void) papiAttributeListGetString(request, NULL, "uri-host", &host);
	(void) papiAttributeListGetString(request, NULL, "uri-path", &path);
	(void) papiAttributeListGetInteger(request, NULL, "uri-port", &port);

	if (port == 631)
		snprintf(buf, sizeof (buf), "ipp://%s%s", host, path);
	else
		snprintf(buf, sizeof (buf), "http://%s:%d%s", host, port, path);

	for (status = papiAttributeListGetCollection(response, &iter,
	    "printer-attributes-group", &group);
	    status == PAPI_OK;
	    status = papiAttributeListGetCollection(NULL, &iter, NULL, &group))
		massage_printer_attributes_group(group, buf);

	iter = NULL;
	for (status = papiAttributeListGetCollection(response, &iter,
	    "job-attributes-group", &group);
	    status == PAPI_OK;
	    status = papiAttributeListGetCollection(NULL, &iter, NULL, &group))
		massage_job_attributes_group(group, buf);
}

/*
 * This walks through the locale tab and returns the installed
 * locales.  There must be a better way.
 */
void
add_supported_locales(papi_attribute_t ***attributes)
{
	FILE *fp;

	papiAttributeListAddString(attributes, PAPI_ATTR_REPLACE,
	    "generated-natural-language-supported", "en-us");

	if ((fp = fopen("/usr/lib/locale/lcttab", "r")) != NULL) {
		char buf[1024];

		while (fgets(buf, sizeof (buf), fp) != NULL) {
			char *name, *file;
			int i, passed = 1;

			name = strtok(buf, " \t\n");
			if (name == NULL)
				continue;

			for (i = 0; ((passed == 1) && (name[i] != '\0')); i++) {
				if (isalpha(name[i]) != 0)
					name[i] = tolower(name[i]);
				else if ((name[i] == '_') || (name[i] == '-'))
					name[i] = '-';
				else
					passed = 0;
			}

			if ((passed == 1) &&
			    ((file = strtok(NULL, " \t\n")) != NULL)) {
					char path[1024];

				snprintf(path, sizeof (path),
				    "/usr/lib/locale/%s", file);

				if (access(path, F_OK) != 0)
					continue;

				papiAttributeListAddString(attributes,
				    PAPI_ATTR_APPEND,
				    "generated-natural-language-supported",
				    name);
			}
		}
		(void) fclose(fp);
	}
}

void
papi_to_ipp_printer_group(papi_attribute_t ***response,
    papi_attribute_t **request, int flags, papi_printer_t p)
{
	papi_attribute_t **ipp_group = NULL;

	copy_attributes(&ipp_group, papiPrinterGetAttributeList(p));

	/* Windows clients appear to have a problem with very large values */
	papiAttributeListDelete(&ipp_group, "lpsched-printer-ppd-contents");

	add_default_attributes(&ipp_group);
	ipp_operations_supported(&ipp_group, request);

	(void) papiAttributeListAddCollection(response, flags,
	    "printer-attributes-group", ipp_group);
	papiAttributeListFree(ipp_group);
}

void
papi_to_ipp_job_group(papi_attribute_t ***response,
    papi_attribute_t **request, int flags, papi_job_t j)
{
	papi_attribute_t **ipp_group = NULL;

	copy_attributes(&ipp_group, papiJobGetAttributeList(j));

	(void) papiAttributeListAddCollection(response, flags,
	    "job-attributes-group", ipp_group);
	papiAttributeListFree(ipp_group);
}
