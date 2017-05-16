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
 * Copyright (c) 2014 Gary Mills
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <papi.h>
#include <regex.h>

#define	MAX_PAGES 32767
/*
 * Assuming the maximum number of pages in
 * a document to be 32767
 */

static void papiAttributeFree(papi_attribute_t *attribute);

static void
papiAttributeValueFree(papi_attribute_value_type_t type,
    papi_attribute_value_t *value)
{
	if (value != NULL) {
		switch (type) {
		case PAPI_STRING:
			if (value->string != NULL)
				free(value->string);
			break;
		case PAPI_COLLECTION:
			if (value->collection != NULL) {
				int i;

				for (i = 0; value->collection[i] != NULL; i++)
					papiAttributeFree(value->collection[i]);

				free(value->collection);
			}
			break;
		default: /* don't need to free anything extra */
			break;
		}

		free(value);
	}
}

static void
papiAttributeValuesFree(papi_attribute_value_type_t type,
    papi_attribute_value_t **values)
{
	if (values != NULL) {
		int i;

		for (i = 0; values[i] != NULL; i++)
			papiAttributeValueFree(type, values[i]);

		free(values);
	}
}

static void
papiAttributeFree(papi_attribute_t *attribute)
{
	if (attribute != NULL) {
		free(attribute->name);
		if (attribute->values != NULL)
			papiAttributeValuesFree(attribute->type,
			    attribute->values);
		free(attribute);
	}
}

void
papiAttributeListFree(papi_attribute_t **list)
{
	if (list != NULL) {
		int i;

		for (i = 0; list[i] != NULL; i++)
			papiAttributeFree(list[i]);

		free(list);
	}
}

static papi_attribute_t **
collection_dup(papi_attribute_t **collection)
{
	papi_attribute_t **result = NULL;

	/* allows a NULL collection that is "empty" or "no value" */
	if (collection != NULL) {
		papi_status_t status = PAPI_OK;
		int i;

		for (i = 0; ((collection[i] != NULL) && (status == PAPI_OK));
		    i++) {
			papi_attribute_t *a = collection[i];

			status = papiAttributeListAddValue(&result,
			    PAPI_ATTR_APPEND, a->name, a->type, NULL);
			if ((status == PAPI_OK) && (a->values != NULL)) {
				int j;

				for (j = 0; ((a->values[j] != NULL) &&
				    (status == PAPI_OK)); j++)
					status = papiAttributeListAddValue(
					    &result, PAPI_ATTR_APPEND,
					    a->name, a->type, a->values[j]);
			}
		}
		if (status != PAPI_OK) {
			papiAttributeListFree(result);
			result = NULL;
		}
	}

	return (result);
}

static papi_attribute_value_t *
papiAttributeValueDup(papi_attribute_value_type_t type,
    papi_attribute_value_t *v)
{
	papi_attribute_value_t *result = NULL;

	if ((v != NULL) && ((result = calloc(1, sizeof (*result))) != NULL)) {
		switch (type) {
		case PAPI_STRING:
			if (v->string == NULL) {
				free(result);
				result = NULL;
			} else
				result->string = strdup(v->string);
			break;
		case PAPI_INTEGER:
			result->integer = v->integer;
			break;
		case PAPI_BOOLEAN:
			result->boolean = v->boolean;
			break;
		case PAPI_RANGE:
			result->range.lower = v->range.lower;
			result->range.upper = v->range.upper;
			break;
		case PAPI_RESOLUTION:
			result->resolution.xres = v->resolution.xres;
			result->resolution.yres = v->resolution.yres;
			result->resolution.units = v->resolution.units;
			break;
		case PAPI_DATETIME:
			result->datetime = v->datetime;
			break;
		case PAPI_COLLECTION:
			result->collection = collection_dup(v->collection);
			break;
		case PAPI_METADATA:
			result->metadata = v->metadata;
			break;
		default:	/* unknown type, fail to duplicate */
			free(result);
			result = NULL;
		}
	}

	return (result);
}

static papi_attribute_t *
papiAttributeAlloc(char *name, papi_attribute_value_type_t type)
{
	papi_attribute_t *result = NULL;

	if ((result = calloc(1, sizeof (*result))) != NULL) {
		result->name = strdup(name);
		result->type = type;
	}

	return (result);
}

static papi_status_t
papiAttributeListAppendValue(papi_attribute_value_t ***values,
    papi_attribute_value_type_t type,
    papi_attribute_value_t *value)
{

	if (values == NULL)
		return (PAPI_BAD_ARGUMENT);

	if (value != NULL) {	/* this allows "empty" attributes */
		papi_attribute_value_t *tmp = NULL;

		if ((tmp = papiAttributeValueDup(type, value)) == NULL)
			return (PAPI_TEMPORARY_ERROR);

		list_append(values, tmp);
	}

	return (PAPI_OK);
}

papi_status_t
papiAttributeListAddValue(papi_attribute_t ***list, int flgs,
    char *name, papi_attribute_value_type_t type,
    papi_attribute_value_t *value)
{
	papi_status_t result;
	int flags = flgs;
	papi_attribute_t *attribute = NULL;
	papi_attribute_value_t **values = NULL;

	if ((list == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((type == PAPI_RANGE) && (value != NULL) &&
	    (value->range.lower > value->range.upper))
		return (PAPI_BAD_ARGUMENT);	/* RANGE must have min <= max */

	if (flags == 0) /* if it wasn't set, set a default behaviour */
		flags = PAPI_ATTR_APPEND;

	/* look for an existing one */
	attribute = papiAttributeListFind(*list, name);

	if (((flags & PAPI_ATTR_EXCL) != 0) && (attribute != NULL))
		return (PAPI_CONFLICT); /* EXISTS */

	if (((flags & PAPI_ATTR_REPLACE) == 0) && (attribute != NULL) &&
	    (attribute->type != type))
		return (PAPI_CONFLICT); /* TYPE CONFLICT */

	/* if we don't have one, create it and add it to the list */
	if ((attribute == NULL) &&
	    ((attribute = papiAttributeAlloc(name, type)) != NULL))
		list_append(list, attribute);

	/* if we don't have one by now, it's most likely an alloc fail */
	if (attribute == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/*
	 * if we are replacing, clear any existing values, but don't free
	 * until after we have replaced the values, in case we are replacing
	 * a collection with a relocated version of the original collection.
	 */
	if (((flags & PAPI_ATTR_REPLACE) != 0) && (attribute->values != NULL)) {
		values = attribute->values;
		attribute->values = NULL;
	}

	attribute->type = type;

	result = papiAttributeListAppendValue(&attribute->values, type, value);

	/* free old values if we replaced them */
	if (values != NULL)
		papiAttributeValuesFree(type, values);

	return (result);
}

papi_status_t
papiAttributeListAddString(papi_attribute_t ***list, int flags,
    char *name, char *string)
{
	papi_attribute_value_t v;

	v.string = (char *)string;
	return (papiAttributeListAddValue(list, flags, name, PAPI_STRING, &v));
}

papi_status_t
papiAttributeListAddInteger(papi_attribute_t ***list, int flags,
    char *name, int integer)
{
	papi_attribute_value_t v;

	v.integer = integer;
	return (papiAttributeListAddValue(list, flags, name, PAPI_INTEGER, &v));
}

papi_status_t
papiAttributeListAddBoolean(papi_attribute_t ***list, int flags,
    char *name, char boolean)
{
	papi_attribute_value_t v;

	v.boolean = boolean;
	return (papiAttributeListAddValue(list, flags, name, PAPI_BOOLEAN, &v));
}

papi_status_t
papiAttributeListAddRange(papi_attribute_t ***list, int flags,
    char *name, int lower, int upper)
{
	papi_attribute_value_t v;

	v.range.lower = lower;
	v.range.upper = upper;
	return (papiAttributeListAddValue(list, flags, name, PAPI_RANGE, &v));
}

papi_status_t
papiAttributeListAddResolution(papi_attribute_t ***list, int flags,
    char *name, int xres, int yres, papi_resolution_unit_t units)
{
	papi_attribute_value_t v;

	v.resolution.xres = xres;
	v.resolution.yres = yres;
	v.resolution.units = units;
	return (papiAttributeListAddValue(list, flags, name,
	    PAPI_RESOLUTION, &v));
}

papi_status_t
papiAttributeListAddDatetime(papi_attribute_t ***list, int flags,
    char *name, time_t datetime)
{
	papi_attribute_value_t v;

	v.datetime = datetime;
	return (papiAttributeListAddValue(list, flags, name,
	    PAPI_DATETIME, &v));
}

papi_status_t
papiAttributeListAddCollection(papi_attribute_t ***list, int flags,
    char *name, papi_attribute_t **collection)
{
	papi_attribute_value_t v;

	v.collection = (papi_attribute_t **)collection;
	return (papiAttributeListAddValue(list, flags, name,
	    PAPI_COLLECTION, &v));
}

papi_status_t
papiAttributeListAddMetadata(papi_attribute_t ***list, int flags,
    char *name, papi_metadata_t metadata)
{
	papi_attribute_value_t v;

	v.metadata = metadata;
	return (papiAttributeListAddValue(list, flags, name,
	    PAPI_METADATA, &v));
}

papi_status_t
papiAttributeListDelete(papi_attribute_t ***list, char *name)
{
	papi_attribute_t *attribute;

	if ((list == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((attribute = papiAttributeListFind(*list, name)) == NULL)
		return (PAPI_NOT_FOUND);

	list_remove(list, attribute);
	papiAttributeFree(attribute);

	return (PAPI_OK);
}

papi_attribute_t *
papiAttributeListFind(papi_attribute_t **list, char *name)
{
	int i;
	if ((list == NULL) || (name == NULL))
		return (NULL);

	for (i = 0; list[i] != NULL; i++)
		if (strcasecmp(list[i]->name, name) == 0)
			return ((papi_attribute_t *)list[i]);

	return (NULL);
}

papi_attribute_t *
papiAttributeListGetNext(papi_attribute_t **list, void **iter)
{
	papi_attribute_t **tmp, *result;

	if ((list == NULL) && (iter == NULL))
		return (NULL);

	if (*iter == NULL)
		*iter = list;

	tmp = *iter;
	result = *tmp;
	*iter = ++tmp;

	return (result);
}

papi_status_t
papiAttributeListGetValue(papi_attribute_t **list, void **iter,
    char *name, papi_attribute_value_type_t type,
    papi_attribute_value_t **value)
{
	papi_attribute_value_t **tmp;
	void *fodder = NULL;

	if ((list == NULL) || ((name == NULL) && (iter == NULL)) ||
	    (value == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (iter == NULL)
		iter = &fodder;

	if ((iter == NULL) || (*iter == NULL)) {
		papi_attribute_t *attr = papiAttributeListFind(list, name);

		if (attr == NULL)
			return (PAPI_NOT_FOUND);

		if (attr->type != type)
			return (PAPI_NOT_POSSIBLE);

		tmp = attr->values;
	} else
		tmp = *iter;

	if (tmp == NULL)
		return (PAPI_NOT_FOUND);

	*value = *tmp;
	*iter =  ++tmp;

	if (*value == NULL)
		return (PAPI_GONE);

	return (PAPI_OK);
}

papi_status_t
papiAttributeListGetString(papi_attribute_t **list, void **iter,
    char *name, char **vptr)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if (vptr == NULL)
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_STRING, &value);
	if (status == PAPI_OK)
		*vptr = value->string;

	return (status);
}

papi_status_t
papiAttributeListGetInteger(papi_attribute_t **list, void **iter,
    char *name, int *vptr)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if (vptr == NULL)
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_INTEGER, &value);
	if (status == PAPI_OK)
		*vptr = value->integer;

	return (status);
}

papi_status_t
papiAttributeListGetBoolean(papi_attribute_t **list, void **iter,
    char *name, char *vptr)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if (vptr == NULL)
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_BOOLEAN, &value);
	if (status == PAPI_OK)
		*vptr = value->boolean;

	return (status);
}

papi_status_t
papiAttributeListGetRange(papi_attribute_t **list, void **iter,
    char *name, int *min, int *max)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if ((min == NULL) || (max == NULL))
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_RANGE, &value);
	if (status == PAPI_OK) {
		*min = value->range.lower;
		*max = value->range.upper;
	}

	return (status);
}

papi_status_t
papiAttributeListGetResolution(papi_attribute_t **list, void **iter,
    char *name, int *x, int *y, papi_resolution_unit_t *units)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if ((x == NULL) || (y == NULL) || (units == NULL))
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_RESOLUTION, &value);
	if (status == PAPI_OK) {
		*x = value->resolution.xres;
		*y = value->resolution.yres;
		*units = value->resolution.units;
	}

	return (status);
}

papi_status_t
papiAttributeListGetDatetime(papi_attribute_t **list, void **iter,
    char *name, time_t *dt)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if (dt == NULL)
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_DATETIME, &value);
	if (status == PAPI_OK) {
		*dt = value->datetime;
	}

	return (status);
}

papi_status_t
papiAttributeListGetCollection(papi_attribute_t **list, void **iter,
    char *name, papi_attribute_t ***collection)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if (collection == NULL)
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_COLLECTION, &value);
	if (status == PAPI_OK) {
		*collection = value->collection;
	}

	return (status);
}

papi_status_t
papiAttributeListGetMetadata(papi_attribute_t **list, void **iter,
    char *name, papi_metadata_t *vptr)
{
	papi_status_t status;
	papi_attribute_value_t *value = NULL;

	if (vptr == NULL)
		return (PAPI_BAD_ARGUMENT);

	status = papiAttributeListGetValue(list, iter, name,
	    PAPI_METADATA, &value);
	if (status == PAPI_OK)
		*vptr = value->metadata;

	return (status);
}


/* The string is modified by this call */
static char *
regvalue(regmatch_t match, char *string)
{
	char *result = NULL;
	if (match.rm_so != match.rm_eo) {
		result = string + match.rm_so;
		*(result + (match.rm_eo - match.rm_so)) = '\0';
	}
	return (result);
}

static papi_attribute_value_type_t
_process_value(char *string, char ***parts)
{
	int i;
	static struct {
		papi_attribute_value_type_t	type;
		size_t vals;
		char *expression;
		int	compiled;
		regex_t re;
	} types[] = {
		{ PAPI_BOOLEAN,	   1, "^(true|false|yes|no)$", 0 },
		{ PAPI_COLLECTION, 1, "^\\{(.+)\\}$", 0 },
		/* PAPI_DATETIME is unsupported, too much like an integer */
		{ PAPI_INTEGER,	   1, "^([+-]{0,1}[[:digit:]]+)$", 0 },
		{ PAPI_RANGE,	   3, "^([[:digit:]]*)-([[:digit:]]*)$", 0 },
		{ PAPI_RESOLUTION, 4, "^([[:digit:]]+)x([[:digit:]]+)dp(i|c)$",
			0 },
		NULL
	};
	regmatch_t matches[4];

	for (i = 0; i < 5; i++) {
		int j;

		if (types[i].compiled == 0) {
			(void) regcomp(&(types[i].re), types[i].expression,
			    REG_EXTENDED|REG_ICASE);
			types[i].compiled = 1;
		}
		if (regexec(&(types[i].re), string, (size_t)types[i].vals,
		    matches, 0) == REG_NOMATCH)
			continue;

		for (j = 0; j < types[i].vals; j++)
			list_append(parts, regvalue(matches[j], string));
		return (types[i].type);
	}

	list_append(parts, string);
	return (PAPI_STRING);
}

static void
_add_attribute_value(papi_attribute_value_t ***list,
    papi_attribute_value_type_t type,
    papi_attribute_value_type_t dtype, char **parts)
{
	papi_attribute_value_t *value = calloc(1, sizeof (*value));

	switch (type) {
	case PAPI_STRING:
		value->string = strdup(parts[0]);
		list_append(list, value);
		break;
	case PAPI_BOOLEAN:
		value->boolean = PAPI_TRUE;
		if ((strcasecmp(parts[0], "false") == 0) ||
		    (strcasecmp(parts[0], "no") == 0))
			value->boolean = PAPI_FALSE;
		list_append(list, value);
		break;
	case PAPI_INTEGER:
		value->integer = atoi(parts[0]);
		list_append(list, value);
		break;
	case PAPI_RANGE:
		if (dtype == PAPI_INTEGER) {
			if (atoi(parts[0]) < 0) {
				/*
				 * Handles -P -x case
				 * which prints from page number 1
				 * till page number x
				 */
				value->range.lower = 1;
				value->range.upper = 0 - (atoi(parts[0]));
			} else {
				value->range.lower = value->range.upper
				    = atoi(parts[0]);
			}
		} else if (dtype == PAPI_RANGE)  {
			if (parts[2] == NULL) {
				value->range.lower = atoi(parts[1]);
				/*
				 * Imposing an artificial limit on
				 * the upper bound for page range.
				 */
				value->range.upper = MAX_PAGES;
			} else if ((parts[1] != NULL) && (parts[2] != NULL)) {
				value->range.lower = atoi(parts[1]);
				value->range.upper = atoi(parts[2]);
			}
		}
		list_append(list, value);
		break;
	case PAPI_RESOLUTION:
		value->resolution.xres = atoi(parts[1]);
		value->resolution.yres = atoi(parts[2]);
		if (parts[3][0] == 'i')
			value->resolution.units = PAPI_RES_PER_INCH;
		else
			value->resolution.units = PAPI_RES_PER_CM;
		list_append(list, value);
		break;
	case PAPI_COLLECTION:
		papiAttributeListFromString(&(value->collection), 0, parts[0]);
		list_append(list, value);
		break;
	}
}

static papi_status_t
_papiAttributeFromStrings(papi_attribute_t ***list, int flags,
    char *key, char **values)
{
	int i;
	papi_status_t result = PAPI_OK;
	papi_attribute_t *attr = calloc(1, sizeof (*attr));

	/* these are specified in the papi spec as ranges */
	char *ranges[] = { "copies-supported", "job-impressions-supported",
				"job-k-octets-supported",
				"job-media-sheets-supported", "page-ranges",
				NULL };

	if ((attr == NULL) || ((attr->name = strdup(key)) == NULL))
		return (PAPI_TEMPORARY_ERROR);

	attr->type = PAPI_METADATA;
	/* these are known ranges */
	for (i = 0; ranges[i] != NULL; i++)
		if (strcasecmp(attr->name, ranges[i]) == 0) {
			attr->type = PAPI_RANGE;
			break;
	}

	if (values != NULL) {
		papi_attribute_value_t **vals = NULL;

		for (i = 0; values[i] != NULL; i++) {
			papi_attribute_value_type_t dtype;
			char **parts = NULL;

			dtype = _process_value(values[i], &parts);
			if (attr->type == PAPI_METADATA)
				attr->type = dtype;
			_add_attribute_value(&vals, attr->type, dtype, parts);
			free(parts);
		}
		attr->values = vals;
	}

	list_append(list, attr);

	return (result);
}

static papi_status_t
_parse_attribute_list(papi_attribute_t ***list, int flags, char *string)
{
	papi_status_t result = PAPI_OK;
	char *ptr;

	if ((list == NULL) || (string == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((ptr = strdup(string)) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	while ((*ptr != '\0') && (result == PAPI_OK)) {
		char *key, **values = NULL;

		/* strip any leading whitespace */
		while (isspace(*ptr) != 0)
			ptr++;

		/* Get the name: name[=value] */
		key = ptr;
		while ((*ptr != '\0') && (*ptr != '=') && (isspace(*ptr) == 0))
			ptr++;

		if (*ptr == '=') {
			*ptr++ = '\0';

			while ((*ptr != '\0') && (isspace(*ptr) == 0)) {
				char *value = ptr;

				if ((*ptr == '\'') || (*ptr == '"')) {
					char q = *ptr++;

					/* quoted string value */
					while ((*ptr != '\0') && (*ptr != q))
						ptr++;
					if (*ptr == q)
						ptr++;
				} else if (*ptr == '{') {
					/* collection */
					while ((*ptr != '\0') && (*ptr != '}'))
						ptr++;
					if (*ptr == '}')
						ptr++;
				} else {
					/* value */
					while ((*ptr != '\0') &&
					    (*ptr != ',') &&
					    (isspace(*ptr) == 0))
						ptr++;
				}
				if (*ptr == ',')
					*ptr++ = '\0';
				list_append(&values, value);
			}
		} else { /* boolean "[no]key" */
			char *value = "true";

			if (strncasecmp(key, "no", 2) == 0) {
				key += 2;
				value = "false";
			}
			list_append(&values, value);
		}
		if (*ptr != '\0')
			*ptr++ = '\0';

		result = _papiAttributeFromStrings(list, flags, key, values);
		free(values);
	}

	return (result);
}

papi_status_t
papiAttributeListFromString(papi_attribute_t ***attrs, int flags, char *string)
{
	papi_status_t result = PAPI_OK;

	if ((attrs != NULL) && (string != NULL) &&
	    ((flags & ~(PAPI_ATTR_APPEND+PAPI_ATTR_REPLACE+PAPI_ATTR_EXCL))
	    == 0)) {
		result = _parse_attribute_list(attrs, flags, string);
	} else {
		result = PAPI_BAD_ARGUMENT;
	}

	return (result);
}

static papi_status_t
papiAttributeToString(papi_attribute_t *attribute, char *delim,
    char *buffer, size_t buflen)
{
	papi_attribute_value_t **values = attribute->values;
	int rc, i;

	if ((attribute->type == PAPI_BOOLEAN) && (values[1] == NULL)) {
		if (values[0]->boolean == PAPI_FALSE) {
			if (isupper(attribute->name[0]) == 0)
				strlcat(buffer, "no", buflen);
			else
				strlcat(buffer, "No", buflen);
		}
		rc = strlcat(buffer, attribute->name, buflen);
	} else {
		strlcat(buffer, attribute->name, buflen);
		rc = strlcat(buffer, "=", buflen);
	}

	if (values == NULL)
		return (PAPI_OK);

	for (i = 0; values[i] != NULL; i++) {
		switch (attribute->type) {
		case PAPI_STRING:
			rc = strlcat(buffer, values[i]->string, buflen);
			break;
		case PAPI_INTEGER: {
			char string[24];

			snprintf(string, sizeof (string), "%d",
			    values[i]->integer);
			rc = strlcat(buffer, string, buflen);
			}
			break;
		case PAPI_BOOLEAN:
			if (values[1] != NULL)
				rc = strlcat(buffer, values[i]->boolean ?
				    "true" : "false", buflen);
			break;
		case PAPI_RANGE: {
			char string[24];

			if (values[i]->range.lower == values[i]->range.upper)
				snprintf(string, sizeof (string), "%d",
				    values[i]->range.lower);
			else
				snprintf(string, sizeof (string), "%d-%d",
				    values[i]->range.lower,
				    values[i]->range.upper);
			rc = strlcat(buffer, string, buflen);
			}
			break;
		case PAPI_RESOLUTION: {
			char string[24];

			snprintf(string, sizeof (string), "%dx%ddp%c",
			    values[i]->resolution.xres,
			    values[i]->resolution.yres,
			    values[i]->resolution.units == PAPI_RES_PER_CM ?
			    'c' : 'i');
			rc = strlcat(buffer, string, buflen);
			}
			break;
		case PAPI_DATETIME: {
			struct tm *tm = localtime(&values[i]->datetime);

			if (tm != NULL) {
				char string[64];

				strftime(string, sizeof (string), "%c", tm);
				rc = strlcat(buffer, string, buflen);
			}}
			break;
		case PAPI_COLLECTION: {
			char *string = alloca(buflen);

			papiAttributeListToString(values[i]->collection,
			    delim, string, buflen);
			rc = strlcat(buffer, string, buflen);
			}
			break;
		default: {
			char string[32];

			snprintf(string, sizeof (string), "unknown-type-0x%x",
			    attribute->type);
			rc = strlcat(buffer, string, buflen);
			}
		}
		if (values[i+1] != NULL)
			rc = strlcat(buffer, ",", buflen);

		if (rc >= buflen)
			return (PAPI_NOT_POSSIBLE);

	}

	return (PAPI_OK);
}

papi_status_t
papiAttributeListToString(papi_attribute_t **attrs,
    char *delim, char *buffer, size_t buflen)
{
	papi_status_t status = PAPI_OK;
	int i;

	if ((attrs == NULL) || (buffer == NULL))
		return (PAPI_BAD_ARGUMENT);

	buffer[0] = '\0';
	if (!delim)
		delim = " ";

	for (i = 0; ((attrs[i] != NULL) && (status == PAPI_OK)); i++) {
		status = papiAttributeToString(attrs[i], delim, buffer, buflen);
		if (attrs[i+1] != NULL)
			strlcat(buffer, delim, buflen);
	}

	return (status);
}

static int
is_in_list(char *value, char **list)
{
	if ((list != NULL) && (value != NULL)) {
		int i;

		for (i = 0; list[i] != NULL; i++)
			if (strcasecmp(value, list[i]) == 0)
				return (0);
	}

	return (1);
}

static papi_status_t
copy_attribute(papi_attribute_t ***list, papi_attribute_t *attribute)
{
	papi_status_t status;
	int i = 0;

	if ((list == NULL) || (attribute == NULL) ||
	    (attribute->values == NULL))
		return (PAPI_BAD_ARGUMENT);

	for (status = papiAttributeListAddValue(list, PAPI_ATTR_EXCL,
	    attribute->name, attribute->type, attribute->values[i]);
	    ((status == PAPI_OK) && (attribute->values[i] != NULL));
	    status = papiAttributeListAddValue(list, PAPI_ATTR_APPEND,
	    attribute->name, attribute->type, attribute->values[i]))
		i++;

	return (status);
}

void
copy_attributes(papi_attribute_t ***result, papi_attribute_t **attributes)
{
	int i;

	if ((result == NULL) || (attributes == NULL))
		return;

	for (i = 0; attributes[i] != NULL; i++)
		copy_attribute(result, attributes[i]);
}

void
split_and_copy_attributes(char **list, papi_attribute_t **attributes,
    papi_attribute_t ***in, papi_attribute_t ***out)
{
	int i;

	if ((list == NULL) || (attributes == NULL))
		return;

	for (i = 0; attributes[i] != NULL; i++)
		if (is_in_list(attributes[i]->name, list) == 0)
			copy_attribute(in, attributes[i]);
		else
			copy_attribute(out, attributes[i]);
}

void
papiAttributeListPrint(FILE *fp, papi_attribute_t **attributes,
    char *prefix_fmt, ...)
{
	char *prefix = NULL;
	char *buffer = NULL;
	char *newfmt = NULL;
	void *mem;
	ssize_t size = 0;
	va_list ap;

	newfmt = malloc(strlen(prefix_fmt) + 2);
	sprintf(newfmt, "\n%s", prefix_fmt);

	va_start(ap, prefix_fmt);
	while (vsnprintf(prefix, size, newfmt, ap) > size) {
		size += 1024;
		mem = realloc(prefix, size);
		if (!mem) goto error;
		prefix = mem;
	}
	va_end(ap);

	if (attributes) {
		size = 0;
		while (papiAttributeListToString(attributes, prefix, buffer,
		    size) != PAPI_OK) {
			size += 1024;
			mem = realloc(buffer, size);
			if (!mem) goto error;
			buffer = mem;
		}
	}

	fprintf(fp, "%s%s\n", prefix, buffer ? buffer : "");
	fflush(fp);

error:
	free(newfmt);
	free(prefix);
	free(buffer);
}
