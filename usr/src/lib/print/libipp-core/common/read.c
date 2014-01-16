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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: read.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <papi.h>
#include <ipp.h>


#define	_ipp_tag_string(id) ipp_tag_string((id), buf, sizeof (buf))

static papi_status_t
read_name_with_language(ipp_reader_t iread, void *fd,
			papi_attribute_t ***message)
{
	char *string;
	uint16_t size;

	/* read the language */
	if (iread(fd, &size, 2) != 2) {
		ipp_set_status(message, PAPI_BAD_REQUEST,
				"read failed: lang len\n");
		return (PAPI_BAD_REQUEST);
	}
	size = (uint16_t)ntohs(size);

	if ((string = alloca(size + 1)) == NULL) {
		ipp_set_status(message, PAPI_TEMPORARY_ERROR,
				"Memory allocation failed");
		return (PAPI_TEMPORARY_ERROR);
	}
	if (iread(fd, string, size) != size) {
		ipp_set_status(message, PAPI_BAD_REQUEST,
				"read failed: lang\n");
		return (PAPI_BAD_REQUEST);
	}

	/* read the text */
	if (iread(fd, &size, 2) != 2) {
		ipp_set_status(message, PAPI_BAD_REQUEST,
				"read failed: text len\n");
		return (PAPI_BAD_REQUEST);
	}
	size = (uint16_t)ntohs(size);

	if ((string = alloca(size + 1)) == NULL) {
		ipp_set_status(message, PAPI_TEMPORARY_ERROR,
				"Memory allocation failed");
		return (PAPI_TEMPORARY_ERROR);
	}
	if (iread(fd, string, size) != size) {
		ipp_set_status(message, PAPI_BAD_REQUEST,
				"read failed: text\n");
		return (PAPI_BAD_REQUEST);
	}

	return (PAPI_OK);
}


static struct {
	int8_t	ipp_type;
	int8_t	size;
} type_info[] = {
	{ VTAG_INTEGER,			4 },
	{ VTAG_ENUM,			4 },
	{ VTAG_BOOLEAN,			1 },
	{ VTAG_RANGE_OF_INTEGER,	8 },
	{ VTAG_RESOLUTION,		9 },
	{ VTAG_DATE_TIME,		11 },
	{ DTAG_MIN,			0 }
};

/* verify that the IPP type and size are compatible */
static int
validate_length(int8_t type, int8_t size)
{
	int i;

	for (i = 0; type_info[i].ipp_type != DTAG_MIN; i++)
		if (type_info[i].ipp_type == type)
			return ((type_info[i].size == size) ? 0 : -1);
	return (0);
}

/* convert tyep IPP type to a type that is marginally compatible */
static int8_t
base_type(int8_t i)
{
	switch (i) {
	case VTAG_ENUM:
	case VTAG_INTEGER:
		return (VTAG_INTEGER);
	case VTAG_URI:
	case VTAG_OCTET_STRING:
	case VTAG_TEXT_WITHOUT_LANGUAGE:
	case VTAG_URI_SCHEME:
	case VTAG_CHARSET:
	case VTAG_NATURAL_LANGUAGE:
	case VTAG_MIME_MEDIA_TYPE:
	case VTAG_NAME_WITHOUT_LANGUAGE:
	case VTAG_KEYWORD:
		return (VTAG_TEXT_WITHOUT_LANGUAGE);
	case VTAG_BOOLEAN:
	case VTAG_RANGE_OF_INTEGER:
	case VTAG_DATE_TIME:
	case VTAG_RESOLUTION:
	default:
		return (i);
	}
}

/* verify that the IPP type is correct for the named attribute */
static papi_status_t
validate_type(char *name, int8_t type)
{
	int8_t t = name_to_ipp_type(name);

	if (t == 0)		/* The attribute is not defined in the RFC */
		return (PAPI_NOT_FOUND);
	else if (t == type)	/* The supplied type matched the RFC type */
		return (PAPI_OK);
	else {			/* The supplied type doesn't match the RFC */
		if (base_type(t) == base_type(type))
			return (PAPI_OK);

		return (PAPI_CONFLICT);
	}
}

/* verify that the IPP value is within specification for the named attribute */
static int
validate_value(papi_attribute_t ***message, char *name, int8_t type, ...)
{
#define	within(a, b, c)	((b >= a) && (b <= c))
	va_list ap;
	int rc = -1;
	int min = min_val_len(type, name),
	    max = max_val_len(type, name);
	char buf[64];	/* For _ipp_<...>_string() */

	va_start(ap, type);
	switch (type) {
	case VTAG_ENUM:
	case VTAG_INTEGER: {
		int32_t i = (int32_t)va_arg(ap, int32_t);

		if (within(min, i, max))
			rc = 0;
		else
			ipp_set_status(message, PAPI_BAD_ARGUMENT,
				"%s(%s): %d: out of range (%d - %d)", name,
				_ipp_tag_string(type), i, min, max);
		}
		break;
	case VTAG_BOOLEAN: {
		int8_t v = (int8_t)va_arg(ap, int);

		if (within(0, v, 1))
			rc = 0;
		else
			ipp_set_status(message, PAPI_BAD_ARGUMENT,
				"%s(%s): %d: out of range (0 - 1)", name,
				_ipp_tag_string(type), v);
		}
		break;
	case VTAG_RANGE_OF_INTEGER: {
		int32_t lower = (int32_t)va_arg(ap, int32_t);
		int32_t upper = (int32_t)va_arg(ap, int32_t);

		if (within(min, lower, max) &&
		    within(min, upper, max))
			rc = 0;
		else
			ipp_set_status(message, PAPI_BAD_ARGUMENT,
				"%s(%s): %d - %d: out of range (%d - %d)", name,
				_ipp_tag_string(type), lower, upper, min, max);
		}
		break;
	case VTAG_URI:
	case VTAG_OCTET_STRING:
	case VTAG_TEXT_WITHOUT_LANGUAGE:
	case VTAG_URI_SCHEME:
	case VTAG_CHARSET:
	case VTAG_NATURAL_LANGUAGE:
	case VTAG_MIME_MEDIA_TYPE:
	case VTAG_NAME_WITHOUT_LANGUAGE: {
		char *v = (char *)va_arg(ap, char *);

		if (strlen(v) < max)
			rc = 0;
		else
			ipp_set_status(message, PAPI_BAD_ARGUMENT,
				"%s(%s): %s: too long (max length: %d)", name,
				_ipp_tag_string(type), v, max);
		}
		break;
	case VTAG_KEYWORD: {
		char *v = (char *)va_arg(ap, char *);

		if (strlen(v) >= max)
			ipp_set_status(message, PAPI_BAD_ARGUMENT,
				"%s(%s): %s: too long (max length: %d)", name,
				_ipp_tag_string(type), v, max);
		else if (is_keyword(v) == 0)
			ipp_set_status(message, PAPI_BAD_ARGUMENT,
				"%s(%s): %s: invalid keyword", name,
				_ipp_tag_string(type), v);
		else
			rc = 0;
		}
		break;
	case VTAG_DATE_TIME:
	case VTAG_RESOLUTION:
	default:
		rc = 0;
	}
	va_end(ap);

	return (rc);
#undef within
}

/*
 * read_attr_group() reads in enough of the message data to parse an entire
 * attribute group.  Since to determine that the group is finished you have to
 * read the character that determines the type of the next group, this function
 * must return that character, in order that our caller knows how to call us for
 * the next group.  Thus type is used both as an input parameter (the type of
 * attribute group to read in) and an output parameter (the type of the next
 * attribute group).
 */

static papi_status_t
ipp_read_attribute_group(ipp_reader_t iread, void *fd, int8_t *type,
			papi_attribute_t ***message)
{
	int8_t value_tag;
	uint16_t name_length, value_length;
	papi_attribute_t **attributes = NULL;
	char *name = NULL;
	int i;
	char buf[64];	/* For _ipp_<...>_string() */

	/*
	 * RFC2910 3.3 says we need to handle `An expected but missing
	 * "begin-attribute-group-tag" field.  How?
	 */
	if (*type > DTAG_MAX)  {
		/* Scream bloody murder, or assign a new type? */
		ipp_set_status(message, PAPI_BAD_REQUEST,
			"Bad attribute group tag 0x%.2hx (%s)",
			*type, _ipp_tag_string(*type));
		return (PAPI_BAD_REQUEST);
	}

	/* This loops through *values* not *attributes*! */
	for (i = 0; ; i++) {
		papi_status_t valid = PAPI_OK;
		if (iread(fd, &value_tag, 1) != 1) {
			ipp_set_status(message, PAPI_BAD_REQUEST,
				"bad read: value tag\n");
			return (PAPI_BAD_REQUEST);
		}
		/* are we done with this group ? */
		if (value_tag <= DTAG_MAX)
			break;

		if (iread(fd, &name_length, 2) != 2) {
			ipp_set_status(message, PAPI_BAD_REQUEST,
				"bad read: name length\n");
			return (PAPI_BAD_REQUEST);
		}
		name_length = (uint16_t)ntohs(name_length);

		/* Not just another value for the previous attribute */
		if (name_length != 0) {
			if ((name = alloca(name_length + 1)) == NULL) {
				ipp_set_status(message, PAPI_TEMPORARY_ERROR,
					"alloca(): failed\n");
				return (PAPI_TEMPORARY_ERROR);
			}
			(void) memset(name, 0, name_length + 1);

			if (iread(fd, name, name_length) != name_length) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: name\n");
				return (PAPI_BAD_REQUEST);
			}
		}

		valid = validate_type(name, value_tag);
		if ((valid != PAPI_OK) && (valid != PAPI_NOT_FOUND))
			ipp_set_status(message, valid, "%s(%s): %s", name,
				_ipp_tag_string(value_tag),
				papiStatusString(valid));

		if (iread(fd, &value_length, 2) != 2) {
			ipp_set_status(message, PAPI_BAD_REQUEST,
				"bad read: value length\n");
			return (PAPI_BAD_REQUEST);
		}
		value_length = (uint16_t)ntohs(value_length);

		if (validate_length(value_tag, value_length) < 0) {
			ipp_set_status(message, PAPI_BAD_REQUEST,
				"Bad value length (%d) for type %s",
				value_length, _ipp_tag_string(value_tag));
			return (PAPI_BAD_REQUEST);
		}

		switch (value_tag) {
		case VTAG_INTEGER:
		case VTAG_ENUM: {
			int32_t v;

			if (iread(fd, &v, value_length) != value_length) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: int/enum\n");
				return (PAPI_BAD_REQUEST);
			}
			v = (int32_t)ntohl(v);
			(void) validate_value(message, name, value_tag, v);
			papiAttributeListAddInteger(&attributes,
						PAPI_ATTR_APPEND, name, v);

			}
			break;
		case VTAG_BOOLEAN: {
			int8_t v;

			if (iread(fd, &v, value_length) != value_length) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: boolean\n");
				return (PAPI_BAD_REQUEST);
			}
			(void) validate_value(message, name, value_tag, v);
			papiAttributeListAddBoolean(&attributes,
						PAPI_ATTR_APPEND, name, v);
			}
			break;
		case VTAG_RANGE_OF_INTEGER: {
			int32_t min, max;

			if (iread(fd, &min, 4) != 4) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: min\n");
				return (PAPI_BAD_REQUEST);
			}
			if (iread(fd, &max, 4) != 4) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: max\n");
				return (PAPI_BAD_REQUEST);
			}
			min = (int32_t)ntohl(min);
			max = (int32_t)ntohl(max);
			(void) validate_value(message, name, value_tag,
					min, max);
			papiAttributeListAddRange(&attributes, PAPI_ATTR_APPEND,
						name, min, max);
			}
			break;
		case VTAG_RESOLUTION: {
			int32_t x, y;
			int8_t units;

			if (iread(fd, &x, 4) != 4) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: x\n");
				return (PAPI_BAD_REQUEST);
			}
			if (iread(fd, &y, 4) != 4) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: y\n");
				return (PAPI_BAD_REQUEST);
			}
			if (iread(fd, &units, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: units\n");
				return (PAPI_BAD_REQUEST);
			}
			x = (int32_t)ntohl(x);
			y = (int32_t)ntohl(y);
			papiAttributeListAddResolution(&attributes,
						PAPI_ATTR_APPEND, name, x, y,
						(papi_resolution_unit_t)units);
			}
			break;
		case VTAG_DATE_TIME: {
			struct tm tm;
			time_t v;
			int8_t c;
			uint16_t s;

			(void) memset(&tm, 0, sizeof (tm));
			if (iread(fd, &s, 2) != 2) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: year\n");
				return (PAPI_BAD_REQUEST);
			}
			tm.tm_year = (uint16_t)ntohs(s) - 1900;
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: month\n");
				return (PAPI_BAD_REQUEST);
			}
			tm.tm_mon = c - 1;
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: day\n");
				return (PAPI_BAD_REQUEST);
			}
			tm.tm_mday = c;
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: hour\n");
				return (PAPI_BAD_REQUEST);
			}
			tm.tm_hour = c;
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: minutes\n");
				return (PAPI_BAD_REQUEST);
			}
			tm.tm_min = c;
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: seconds\n");
				return (PAPI_BAD_REQUEST);
			}
			tm.tm_sec = c;
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: decisec\n");
				return (PAPI_BAD_REQUEST);
			}
			/* tm.deciseconds = c; */
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: utc_dir\n");
				return (PAPI_BAD_REQUEST);
			}
			/* tm.utc_dir = c; */
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: utc_hour\n");
				return (PAPI_BAD_REQUEST);
			}
			/* tm.utc_hours = c; */
			if (iread(fd, &c, 1) != 1) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: utc_min\n");
				return (PAPI_BAD_REQUEST);
			}
			/* tm.utc_minutes = c; */

			v = mktime(&tm);

			(void) validate_value(message, name, value_tag, v);
			papiAttributeListAddDatetime(&attributes,
						PAPI_ATTR_APPEND, name, v);
			}
			break;
		case VTAG_NAME_WITH_LANGUAGE:
		case VTAG_TEXT_WITH_LANGUAGE:
			/*
			 * we are dropping this because we don't support
			 * name with language at this time.
			 */
			(void) read_name_with_language(iread, fd, message);
			break;
		case VTAG_NAME_WITHOUT_LANGUAGE:
		case VTAG_TEXT_WITHOUT_LANGUAGE:
		case VTAG_URI:
		case VTAG_KEYWORD:
		case VTAG_CHARSET: {
			char *v;

			if ((v = calloc(1, value_length + 1)) == NULL) {
				ipp_set_status(message, PAPI_TEMPORARY_ERROR,
					"calloc(): failed\n");
				return (PAPI_TEMPORARY_ERROR);
			}
#ifdef NOTDEF
			if (iread(fd, v, value_length) != value_length) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: stringy\n");
				return (PAPI_BAD_REQUEST);
			}
#else
			{
			int rc, i = value_length;
			char *p = v;

			while ((rc = iread(fd, p, i)) != i) {
				if (rc <= 0) {
					ipp_set_status(message,
						PAPI_BAD_REQUEST,
						"bad read: stringy\n");
					return (PAPI_BAD_REQUEST);
				}
				i -= rc;
				p += rc;
			}
			}
#endif
			(void) validate_value(message, name, value_tag, v);
			papiAttributeListAddString(&attributes,
						PAPI_ATTR_APPEND, name, v);
			}
			break;
		case VTAG_UNKNOWN:
		case VTAG_NOVALUE:
		case VTAG_UNSUPPORTED:
			papiAttributeListAddValue(&attributes, PAPI_ATTR_EXCL,
					name, PAPI_COLLECTION, NULL);
			break;
		default: {
			char *v;

			if ((v = calloc(1, value_length + 1)) == NULL) {
				ipp_set_status(message, PAPI_TEMPORARY_ERROR,
					"calloc(): failed\n");
				return (PAPI_TEMPORARY_ERROR);
			}
			if (iread(fd, v, value_length) != value_length) {
				ipp_set_status(message, PAPI_BAD_REQUEST,
					"bad read: other\n");
				return (PAPI_BAD_REQUEST);
			}
			papiAttributeListAddString(&attributes,
						PAPI_ATTR_APPEND, name, v);
			}
			break;
		}
	}

	if (attributes != NULL) {
		char name[32];

		(void) ipp_tag_string(*type, name, sizeof (name));
		papiAttributeListAddCollection(message, PAPI_ATTR_APPEND, name,
					attributes);
	}

	*type = value_tag;

	return (PAPI_OK);
}


static papi_status_t
ipp_read_header(ipp_reader_t iread, void *fd, papi_attribute_t ***message,
		char type)
{
	char *attr_name = "status-code";	/* default to a response */
	char buf[8];
	int8_t c;
	uint16_t s;
	int32_t i;

	if ((iread == NULL) || (fd == NULL) || (message == NULL))
		return (PAPI_BAD_ARGUMENT);

	/*
	 * Apache 1.X uses the buffer supplied to it's read call to read in
	 * the chunk size when chunking is used.  This causes problems
	 * reading the header a piece at a time, because we don't have
	 * enough room to read in the chunk size prior to reading the
	 * chunk.
	 */

	if (iread(fd, buf, 8) != 8)
		return (PAPI_BAD_REQUEST);

	c = buf[0];
	(void) papiAttributeListAddInteger(message, PAPI_ATTR_REPLACE,
				"version-major", c);

	c = buf[1];
	(void) papiAttributeListAddInteger(message, PAPI_ATTR_REPLACE,
				"version-minor", c);

	memcpy(&s, &buf[2], 2);
	s = (uint16_t)ntohs(s);
	if (type == IPP_TYPE_REQUEST)
		attr_name = "operation-id";
	(void) papiAttributeListAddInteger(message, PAPI_ATTR_REPLACE,
				attr_name, s);

	memcpy(&i, &buf[4], 4);
	i = (uint32_t)ntohl(i);
	(void) papiAttributeListAddInteger(message, PAPI_ATTR_REPLACE,
				"request-id", i);

	return (PAPI_OK);
}

static papi_status_t
ipp_read_attribute_groups(ipp_reader_t iread, void *fd,
			papi_attribute_t ***message)
{
	papi_status_t result = PAPI_OK;
	int8_t tag;

	/* start reading the attribute groups */
	if (iread(fd, &tag, 1) != 1)	/* prime the pump */
		return (PAPI_BAD_REQUEST);

	while ((tag != DTAG_END_OF_ATTRIBUTES) && (result == PAPI_OK)) {
		result = ipp_read_attribute_group(iread, fd, &tag, message);
	}

	return (result);
}

papi_status_t
ipp_read_message(ipp_reader_t iread, void *fd, papi_attribute_t ***message,
		char type)
{
	papi_status_t result = PAPI_OK;

	if ((iread == NULL) || (fd == NULL) || (message == NULL))
		return (PAPI_BAD_ARGUMENT);

	result = ipp_read_header(iread, fd, message, type);
	if (result == PAPI_OK)
		result = ipp_read_attribute_groups(iread, fd, message);

	return (result);
}
