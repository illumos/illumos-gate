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
 * Copyright 2017 Gary Mills
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains an extremely rudimentary implementation of PPD file
 * parsing support.  The parsing done here converts the contents of a PPD
 * file into a set of PAPI attributes that applications can use to build
 * print panels.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <papi.h>

static void
process_line(char *line, char **key, char **value, char **comment)
{
	char *ptr, *ptr2;

	*key = &line[1];
	*value = NULL;
	*comment = NULL;

	if ((ptr = strchr(line, ':')) == NULL)
		return;

	/*
	 * line is in the form:
	 *    *key: value/comment
	 * or
	 *    *key value/comment: data
	 */
	*ptr++ = NULL;
	while (isspace(*ptr) != 0)
		ptr++;

	if ((ptr2 = strchr(line, ' ')) != NULL) {
		ptr = ptr2;
		/*
		 * line is in the form:
		 *    *key value/comment: data
		 */
		*ptr++ = NULL;
		while (*ptr == ' ')
			ptr++;
	}

	if (*ptr == '*')
		ptr++;

	*value = ptr;

	if ((ptr = strchr(ptr, '/')) != NULL) {
		*ptr++ = NULL;
		*comment = ptr;
	}
}

papi_status_t
PPDFileToAttributesList(papi_attribute_t ***attributes, char *filename)
{
	papi_status_t status = PAPI_OK;
	FILE *fp;
	char line[256];
	char capability[256];
	char def[256];
	char supported[256];

	int ui = 0;

	if ((fp = fopen(filename, "r")) == NULL)
		return (PAPI_NOT_POSSIBLE);

	while ((status == PAPI_OK) &&
			(fgets(line, sizeof (line), fp) != NULL)) {
		char *key = NULL, *value = NULL, *text = NULL;

		/* we want *key...: "value" */
		if (line[0] != '*')
			continue;

		if (strchr(line, ':') == NULL)
			continue;

		if ((text = strrchr(line, '\n')) != NULL)
			*text = NULL;

		process_line(line, &key, &value, &text);

		if ((strcasecmp(key, "PageSize") == 0) ||
		    (strcasecmp(key, "InputSlot") == 0))
			key = "media";

		if (strcasecmp(key, "OpenGroup") == 0) {
			if (value == NULL)
				value = "unknown";
		} else if (strcasecmp(key, "OpenUI") == 0) {
			if ((strcasecmp(value, "PageSize") == 0) ||
			    (strcasecmp(value, "InputSlot") == 0))
				value = "media";
			snprintf(capability, sizeof (capability), "%s", value);
			snprintf(def, sizeof (def),
					"%s-default", value);
			snprintf(supported, sizeof (supported),
					"%s-supported", value);
			ui = 1;
		} else if (strcasecmp(key, "CloseGroup") == 0) {
			/* do nothing */
		} else if (strcasecmp(key, "CloseUI") == 0) {
			ui = 0;
			/* do nothing */
		} else if (strcasecmp(key, "Manufacturer") == 0) {
			status = papiAttributeListAddString(attributes,
					PAPI_ATTR_EXCL,
					"printer-make", value);
		} else if (strcasecmp(key, "ModelName") == 0) {
			status = papiAttributeListAddString(attributes,
					PAPI_ATTR_EXCL,
					"printer-model", value);
		} else if (strcasecmp(key, "ShortNickName") == 0) {
			status = papiAttributeListAddString(attributes,
					PAPI_ATTR_EXCL,
					"printer-make-and-model", value);
		} else if ((strncasecmp(key, "Default", 7) == 0) && ui) {
			status = papiAttributeListAddString(attributes,
					PAPI_ATTR_EXCL,
					def, value);
		} else if ((strcasecmp(key, capability) == 0) && ui) {
			status = papiAttributeListAddString(attributes,
					PAPI_ATTR_APPEND,
					supported, value);
		}
	}
	fclose(fp);

	return (status);
}
