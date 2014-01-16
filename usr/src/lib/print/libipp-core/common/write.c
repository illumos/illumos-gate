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

/* $Id: write.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <papi.h>
#include <ipp.h>

static int8_t
papi_attribute_to_ipp_type(papi_attribute_value_type_t type)
{
	switch (type) {
	case PAPI_INTEGER:
		return (VTAG_INTEGER);
	case PAPI_BOOLEAN:
		return (VTAG_BOOLEAN);
	case PAPI_RANGE:
		return (VTAG_RANGE_OF_INTEGER);
	case PAPI_RESOLUTION:
		return (VTAG_RESOLUTION);
	case PAPI_DATETIME:
		return (VTAG_DATE_TIME);
	case PAPI_STRING:
		return (VTAG_TEXT_WITHOUT_LANGUAGE);
	}

	return (0);
}

static papi_status_t
papi_ipp_type_match(papi_attribute_value_type_t papi, int8_t ipp)
{
	switch (papi) {
	case PAPI_STRING:
		switch (ipp) {
		case VTAG_URI:
		case VTAG_OCTET_STRING:
		case VTAG_TEXT_WITHOUT_LANGUAGE:
		case VTAG_URI_SCHEME:
		case VTAG_CHARSET:
		case VTAG_NATURAL_LANGUAGE:
		case VTAG_MIME_MEDIA_TYPE:
		case VTAG_NAME_WITHOUT_LANGUAGE:
		case VTAG_KEYWORD:
			break;
		default:
			return (PAPI_CONFLICT);
		}
		break;
	case PAPI_INTEGER:
		switch (ipp) {
		case VTAG_ENUM:
		case VTAG_INTEGER:
			break;
		default:
			return (PAPI_CONFLICT);
		}
		break;
	case PAPI_BOOLEAN:
		if (ipp != VTAG_BOOLEAN)
			return (PAPI_CONFLICT);
		break;
	case PAPI_RANGE:
		if (ipp != VTAG_RANGE_OF_INTEGER)
			return (PAPI_CONFLICT);
		break;
	case PAPI_RESOLUTION:
		if (ipp != VTAG_RESOLUTION)
			return (PAPI_CONFLICT);
		break;
	case PAPI_DATETIME:
		if (ipp != VTAG_DATE_TIME)
			return (PAPI_CONFLICT);
		break;
	case PAPI_COLLECTION:
		/* don't need to match */
		break;
	}

	return (PAPI_OK);
}

static papi_status_t
ipp_write_attribute(ipp_writer_t iwrite, void *fd, papi_attribute_t *attribute)
{
	papi_status_t status;
	papi_attribute_value_t	**values;
	int8_t type;
	int i;
	char *name;

	name = attribute->name;
	values = attribute->values;

	if ((type = name_to_ipp_type(name)) == 0)
		type = papi_attribute_to_ipp_type(attribute->type);

	/* The types don't match, so don't send the attribute */
	if ((status = papi_ipp_type_match(attribute->type, type)) != PAPI_OK)
		return (status);

	if (values == NULL) {
		uint16_t length;

		type = VTAG_UNSUPPORTED;
		if (iwrite(fd, &type, 1) != 1)
			return (PAPI_DEVICE_ERROR);

		if (name != NULL) {	/* first value gets named */
			length = (uint16_t)htons(strlen(name));

			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, name, strlen(name)) != strlen(name))
				return (PAPI_DEVICE_ERROR);
		}

		length = (uint16_t)htons(0);
		if (iwrite(fd, &length, 2) != 2)
			return (PAPI_DEVICE_ERROR);

		return (PAPI_OK);
	}



	for (i = 0; values[i] != NULL; i++) {
		papi_attribute_value_t	*value = values[i];
		uint16_t length = 0;

		if (iwrite(fd, &type, 1) != 1)
			return (PAPI_DEVICE_ERROR);

		if (name != NULL) {	/* first value gets named */
			length = (uint16_t)htons(strlen(name));

			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, name, strlen(name)) != strlen(name))
				return (PAPI_DEVICE_ERROR);
			name = NULL;
		} else {
			length = (uint16_t)htons(0);

			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
		}

		switch (attribute->type) {
		case PAPI_STRING: {
			char *v = (char *)value->string;

			if (v != NULL) {
				size_t str_length = strlen(v);

				/*
				 * if the length is more than 16 bits can
				 * express, send what can be represented
				 * in 16 bits. IPP "strings" can only be
				 * that large.
				 */
				if (str_length > 0xFFFF)
					str_length = 0xFFFF;

				length = (uint16_t)htons(str_length);
				if (iwrite(fd, &length, 2) != 2)
					return (PAPI_DEVICE_ERROR);
				if (iwrite(fd, v, str_length) != str_length)
					return (PAPI_DEVICE_ERROR);
			} else
				if (iwrite(fd, &length, 2) != 2)
					return (PAPI_DEVICE_ERROR);
			}
			break;
		case PAPI_BOOLEAN: {
			int8_t v = (int8_t)value->boolean;

			length = (uint16_t)htons(1);
			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &v, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			}
			break;
		case PAPI_INTEGER: {
			int32_t v = (int32_t)value->integer;

			length = (uint16_t)htons(4);
			v = (int32_t)htonl(v);
			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &v, 4) != 4)
				return (PAPI_DEVICE_ERROR);
			}
			break;
		case PAPI_RANGE: {
			int32_t min = (int32_t)htonl((int)(value->range).lower),
				max = (int32_t)htonl((int)(value->range).upper);

			length = (uint16_t)htons(8);
			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &min, 4) != 4)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &max, 4) != 4)
				return (PAPI_DEVICE_ERROR);
			}
			break;
		case PAPI_RESOLUTION: {
			int32_t x = (int)(value->resolution).xres,
				y = (int)(value->resolution).yres;
			int8_t units = (int8_t)(value->resolution).units;

			length = (uint16_t)htons(9);
			x = (int32_t)htonl(x);
			y = (int32_t)htonl(y);

			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &x, 4) != 4)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &y, 4) != 4)
				return (PAPI_DEVICE_ERROR);
			if (iwrite(fd, &units, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			}
			break;
		case PAPI_DATETIME: {
			struct tm *v = gmtime(&value->datetime);
			int8_t c;
			uint16_t s;

			length = (uint16_t)htons(11);
			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			s = (uint16_t)htons(v->tm_year + 1900);
			if (iwrite(fd, &s, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			c = v->tm_mon + 1;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = v->tm_mday;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = v->tm_hour;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = v->tm_min;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = v->tm_sec;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = /* v->deciseconds */ 0;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = /* v->utc_dir */ 0;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = /* v->utc_hours */ 0;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			c = /* v->utc_minutes */ 0;
			if (iwrite(fd, &c, 1) != 1)
				return (PAPI_DEVICE_ERROR);
			}
			break;
		default: {
			/*
			 * If there is a value, it is not one of our
			 * types, so we couldn't use it anyway.  We assume
			 * that it was an OOB type with no value
			 */
			length = (uint16_t)htons(0);
			if (iwrite(fd, &length, 2) != 2)
				return (PAPI_DEVICE_ERROR);
			}
			break;
		}
	}

	return (PAPI_OK);
}

static papi_status_t
ipp_write_attribute_group(ipp_writer_t iwrite, void *fd, int8_t type,
		papi_attribute_t **attributes)
{
	papi_status_t result = PAPI_OK;
	int i;

	/* write group tag */
	if (iwrite(fd, &type, 1) != 1)
		return (PAPI_DEVICE_ERROR);

	/* write values */
	for (i = 0; ((attributes[i] != NULL) && (result == PAPI_OK)); i++)
		result = ipp_write_attribute(iwrite, fd, attributes[i]);

	return (result);
}

static papi_status_t
ipp_write_attribute_groups(ipp_writer_t iwrite, void *fd,
		papi_attribute_t **groups)
{
	papi_status_t result = PAPI_OK;
	int8_t	c;

	for (c = DTAG_MIN; c <= DTAG_MAX; c++) {
		papi_status_t status;
		papi_attribute_t **group = NULL;
		void *iter = NULL;
		char name[32];

		(void) ipp_tag_string(c, name, sizeof (name));
		for (status = papiAttributeListGetCollection(groups, &iter,
						name, &group);
			((status == PAPI_OK) && (result == PAPI_OK));
			status = papiAttributeListGetCollection(groups, &iter,
						NULL, &group))
				result = ipp_write_attribute_group(iwrite, fd,
								c, group);
	}

	c = DTAG_END_OF_ATTRIBUTES;
	if (iwrite(fd, &c, 1) != 1)
		result = PAPI_DEVICE_ERROR;

	return (result);
}

static papi_status_t
ipp_write_message_header(ipp_writer_t iwrite, void *fd,
		papi_attribute_t **message)
{
	int tmp;
	int8_t c;
	uint16_t s;
	int32_t i;

	/* write the version */
	papiAttributeListGetInteger(message, NULL, "version-major", &tmp);
	c = tmp;
	if (iwrite(fd, &c, 1) != 1)
		return (PAPI_DEVICE_ERROR);

	papiAttributeListGetInteger(message, NULL, "version-minor", &tmp);
	c = tmp;
	if (iwrite(fd, &c, 1) != 1)
		return (PAPI_DEVICE_ERROR);

	/* write the request/status code */
	papiAttributeListGetInteger(message, NULL, "status-code", &tmp);
	papiAttributeListGetInteger(message, NULL, "operation-id", &tmp);
	s = (uint16_t)htons(tmp);
	if (iwrite(fd, &s, 2) != 2)
		return (PAPI_DEVICE_ERROR);

	/* write the request id */
	papiAttributeListGetInteger(message, NULL, "request-id", &tmp);
	i = (uint32_t)htonl(tmp);
	if (iwrite(fd, &i, 4) != 4)
		return (PAPI_DEVICE_ERROR);

	return (PAPI_OK);
}

papi_status_t
ipp_write_message(ipp_writer_t iwrite, void *fd, papi_attribute_t **message)
{
	papi_status_t result;

	if ((iwrite == NULL) || (fd == NULL) || (message == NULL))
		return (PAPI_BAD_ARGUMENT);

	result = ipp_write_message_header(iwrite, fd, message);
	if (result == PAPI_OK)
		result = ipp_write_attribute_groups(iwrite, fd, message);

	return (result);
}
