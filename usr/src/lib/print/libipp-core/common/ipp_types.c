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

/* $Id: ipp_types.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ipp.h>
#include <errno.h>
#include <values.h>

#ifndef MININT
#define	MININT	(-MAXINT - 1)
#endif

typedef struct {
	char *name;
	int8_t ipp_type;
	int min;
	int max;
} attr_info_list_t;

static attr_info_list_t attr_list[] = {
	{"operation-attribute-group", DTAG_OPERATION_ATTRIBUTES, 0, 0},
	{"job-attribute-group", DTAG_JOB_ATTRIBUTES, 0, 0},
	{"printer-attribute-group", DTAG_PRINTER_ATTRIBUTES, 0, 0},
	{"unsupported-attribute-group", DTAG_UNSUPPORTED_ATTRIBUTES, 0, 0},
	{"subscription-attribute-group", DTAG_SUBSCRIPTION_ATTRIBUTES, 0, 0},
	{"even-notificaton-attribute-group",
		DTAG_EVENT_NOTIFICATION_ATTRIBUTES, 0, 0},
	{"attributes-charset", VTAG_CHARSET, 0, 255},
	{"attributes-natural-language", VTAG_NATURAL_LANGUAGE, 0, 255},
	{"charset-configured", VTAG_CHARSET, 0, 255},
	{"charset-supported", VTAG_CHARSET, 0, 255},
	{"color-supported", VTAG_BOOLEAN, 0, 1},
	{"compression", VTAG_KEYWORD, 1, 255},
	{"compression-supported", VTAG_KEYWORD, 1, 255},
	{"copies", VTAG_INTEGER, 1, MAXINT},
	{"copies-default", VTAG_INTEGER, 1, MAXINT},
	{"copies-supported", VTAG_RANGE_OF_INTEGER, 1, MAXINT},
	{"date-at-completed", VTAG_DATE_TIME, 0, 0},
	{"date-at-creation", VTAG_DATE_TIME, 0, 0},
	{"date-at-processing", VTAG_DATE_TIME, 0, 0},
	{"detailed-status-message", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 1023},
	{"document-access-error", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 1023},
	{"document-format", VTAG_MIME_MEDIA_TYPE, 0, 255},
	{"document-format-default", VTAG_MIME_MEDIA_TYPE, 0, 255},
	{"document-format-supported", VTAG_MIME_MEDIA_TYPE, 0, 255},
	{"document-name", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"document-name", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"document-natural-language", VTAG_NATURAL_LANGUAGE, 0, 255},
	{"finishing", VTAG_ENUM, 3, 31},
	{"finishing-default", VTAG_ENUM, 3, 31},
	{"finishing-supported", VTAG_ENUM, 3, 31},
	{"generated-natural-language-supported", VTAG_NATURAL_LANGUAGE, 0, 255},
	{"ipp-attribute-fidelity", VTAG_BOOLEAN, 0, 1},
	{"ipp-versions-supported", VTAG_KEYWORD, 1, 255},
	{"job-detailed-status-messages", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 1023},
	{"job-document-access-errors", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 1023},
	{"job-hold-until", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-hold-until-default", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-hold-until-supported", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-id", VTAG_INTEGER, 1, MAXINT},
	{"job-impressions", VTAG_INTEGER, 0, MAXINT},
	{"job-impressions-completed", VTAG_INTEGER, 0, MAXINT},
	{"job-impressions-supported", VTAG_RANGE_OF_INTEGER, 0, MAXINT},
	{"job-k-octets", VTAG_INTEGER, 0, MAXINT},
	{"job-k-octets-processed", VTAG_INTEGER, 0, MAXINT},
	{"job-k-octets-supported", VTAG_RANGE_OF_INTEGER, 0, MAXINT},
	{"job-media-sheets", VTAG_INTEGER, 0, MAXINT},
	{"job-media-sheets-completed", VTAG_INTEGER, 0, MAXINT},
	{"job-media-sheets-supported", VTAG_RANGE_OF_INTEGER, 0, MAXINT},
	{"job-message-from-operator", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 127},
	{"job-more-info", VTAG_URI, 0, 1023},
	{"job-name", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-originating-user-name", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-printer-up-time", VTAG_INTEGER, 1, MAXINT},
	{"job-printer-uri", VTAG_URI, 0, 1023},
	{"job-priority", VTAG_INTEGER, 1, 100},
	{"job-priority-default", VTAG_INTEGER, 1, 100},
	{"job-priority-supported", VTAG_INTEGER, 1, 100},
	{"job-sheets", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-sheets-default", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-sheets-supported", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"job-state", VTAG_ENUM, 3, 9},
	{"job-state-message", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 1023},
	{"job-state-reasons", VTAG_KEYWORD, 1, 255},
	{"job-uri", VTAG_URI, 0, 1023},
	{"last-document", VTAG_BOOLEAN, 0, 1},
	{"limit", VTAG_INTEGER, 1, MAXINT},
	{"media", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"media-default", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"media-supported", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"message", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 127},
	{"multiple-document-handling", VTAG_KEYWORD, 1, 255},
	{"multiple-document-handling-default", VTAG_KEYWORD, 1, 255},
	{"multiple-document-handling-supported", VTAG_KEYWORD, 1, 255},
	{"multiple-document-jobs-supported", VTAG_BOOLEAN, 0, 1},
	{"multiple-operation-time-out", VTAG_INTEGER, 1, MAXINT},
	{"my-jobs", VTAG_BOOLEAN, 0, 1},
	{"natural-language-configured", VTAG_NATURAL_LANGUAGE, 0, 255},
	{"number-of-documents", VTAG_INTEGER, 0, MAXINT},
	{"number-of-intervening-jobs", VTAG_INTEGER, 0, MAXINT},
	{"number-up", VTAG_INTEGER, 1, MAXINT},
	{"number-up-default", VTAG_INTEGER, 1, MAXINT},
	{"number-up-supported", VTAG_INTEGER, 1, MAXINT},
	{"operations-supported", VTAG_ENUM, 1, 0x8FFF},
	{"orientation-requested", VTAG_ENUM, 3, 6},
	{"orientation-requested-default", VTAG_ENUM, 3, 6},
	{"orientation-requested-supported", VTAG_ENUM, 3, 6},
	{"output-device-assigned", VTAG_NAME_WITHOUT_LANGUAGE, 0, 127},
	{"page-ranges", VTAG_RANGE_OF_INTEGER, 1, MAXINT},
	{"page-ranges-supported", VTAG_BOOLEAN, 0, 1},
	{"pages-per-minute", VTAG_INTEGER, 0, MAXINT},
	{"pages-per-minute-color", VTAG_INTEGER, 0, MAXINT},
	{"pdl-override-supported", VTAG_KEYWORD, 1, 255},
	{"print-quality", VTAG_ENUM, 3, 5},
	{"print-quality-default", VTAG_ENUM, 3, 5},
	{"print-quality-supported", VTAG_ENUM, 3, 5},
	{"printer-current-time", VTAG_DATE_TIME, 0, 1},
	{"printer-driver-installer", VTAG_URI, 0, 1023},
	{"printer-id", VTAG_INTEGER, 1, MAXINT},
	{"printer-info", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 127},
	{"printer-is-accepting-jobs", VTAG_BOOLEAN, 0, 1},
	{"printer-location", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 127},
	{"printer-make-and-model", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 127},
	{"printer-message-from-operator", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 127},
	{"printer-more-info", VTAG_URI, 0, 1023},
	{"printer-more-info-manufacturer", VTAG_URI, 0, 1023},
	{"printer-name", VTAG_NAME_WITHOUT_LANGUAGE, 0, 127},
	{"printer-resolution", VTAG_RESOLUTION, 0, 0},
	{"printer-resolution-default", VTAG_RESOLUTION, 0, 0},
	{"printer-resolution-supported", VTAG_RESOLUTION, 0, 0},
	{"printer-state", VTAG_ENUM, 3, 5},
	{"printer-state-message", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 1023},
	{"printer-state-reasons", VTAG_KEYWORD, 1, 255},
	{"printer-up-time", VTAG_INTEGER, 1, MAXINT},
	{"printer-uri", VTAG_URI, 0, 1023},
	{"printer-uri-supported", VTAG_URI, 0, 1023},
	{"queued-job-count", VTAG_INTEGER, 0, MAXINT},
	{"reference-uri-schemes-supported", VTAG_URI_SCHEME, 0, 63},
	{"requested-attributes", VTAG_KEYWORD, 1, 255},
	{"requesting-user-name", VTAG_NAME_WITHOUT_LANGUAGE, 0, 255},
	{"sides", VTAG_KEYWORD, 1, 255},
	{"sides-default", VTAG_KEYWORD, 1, 255},
	{"sides-supported", VTAG_KEYWORD, 1, 255},
	{"status-code", VTAG_ENUM, 1, 0x7FFF},
	{"status-message", VTAG_TEXT_WITHOUT_LANGUAGE, 0, 255},
	{"time-at-completed", VTAG_INTEGER, MININT, MAXINT},
	{"time-at-creation", VTAG_INTEGER, MININT, MAXINT},
	{"time-at-processing", VTAG_INTEGER, MININT, MAXINT},
	{"uri-authentication-supported", VTAG_KEYWORD, 1, 255},
	{"uri-security-supported", VTAG_KEYWORD, 1, 255},
	{"which-jobs", VTAG_KEYWORD, 1, 255},
	{NULL, 0, 0, 0}
};


static attr_info_list_t *
get_attr_info_by_name(char *name)
{
	if (name != NULL) {
		int i;

		for (i = 0; attr_list[i].name != NULL; i++)
			if (strcasecmp(attr_list[i].name, name) == 0)
				return (&attr_list[i]);
	}

	return (NULL);
}

size_t
max_val_len(int8_t type, char *name)
{
	attr_info_list_t *t;
	int result;

	switch (type) {
	case VTAG_INTEGER:
	case VTAG_RANGE_OF_INTEGER:
	case VTAG_ENUM:
		result = MAXINT;
		break;
	case VTAG_URI:
	case VTAG_OCTET_STRING:
	case VTAG_TEXT_WITHOUT_LANGUAGE:
		result = 1023;
		break;
	case VTAG_NATURAL_LANGUAGE:
	case VTAG_URI_SCHEME:
	case VTAG_CHARSET:
		result = 63;
		break;
	case VTAG_NAME_WITHOUT_LANGUAGE:
	case VTAG_MIME_MEDIA_TYPE:
	case VTAG_KEYWORD:
		result = 255;
		break;
	default:
		result = MAXINT;
	}

#define	min(a, b)	((a < b) ? a : b)
	if ((t = get_attr_info_by_name(name)) != NULL)
		result = min(t->max, result);
#undef min

	return (result);
}

size_t
min_val_len(int8_t type, char *name)
{
	attr_info_list_t *t;
	int result;

	switch (type) {
	case VTAG_INTEGER:
	case VTAG_RANGE_OF_INTEGER:
		result = MININT;
		break;
	case VTAG_ENUM:
		result = 1;
		break;
	case VTAG_URI:
	case VTAG_OCTET_STRING:
	case VTAG_TEXT_WITHOUT_LANGUAGE:
	case VTAG_MIME_MEDIA_TYPE:
	case VTAG_NAME_WITHOUT_LANGUAGE:
	case VTAG_URI_SCHEME:
	case VTAG_CHARSET:
	case VTAG_NATURAL_LANGUAGE:
		result = 0;
		break;
	case VTAG_KEYWORD:
		result = 1;
		break;
	default:
		result = MININT;
	}

#define	max(a, b)	((a > b) ? a : b)
	if ((t = get_attr_info_by_name(name)) != NULL)
		result = max(t->min, result);
#undef max

	return (result);
}

int
is_keyword(char *k)
{
	/* [a-z][a-z0-9._-]* */
	if (*k < 'a' && *k > 'z')
		return (0);
	while (*(++k) != '\0')
		if (*k < 'a' && *k > 'z' && *k < '0' && *k > '9' &&
			*k != '.' && *k != '_' && *k != '-')
			return (0);
	return (1);
}

int8_t
name_to_ipp_type(char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; attr_list[i].name != NULL; i++)
			if (strcasecmp(attr_list[i].name, name) == 0)
				return (attr_list[i].ipp_type);

	return (0);
}
