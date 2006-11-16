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

/* $Id: attribute.c 157 2006-04-26 15:07:55Z ktou $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <alloca.h>
#include <papi.h>

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
		if (attribute->name != NULL)
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
					PAPI_ATTR_APPEND, a->name, a->type,
					NULL);
			if ((status == PAPI_OK) && (a->values != NULL)) {
				int j;

				for (j = 0; ((a->values[j] != NULL) &&
					     (status == PAPI_OK)); j++)
					status = papiAttributeListAddValue(
							&result,
							PAPI_ATTR_APPEND,
							a->name, a->type,
							a->values[j]);
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
			char *name, int xres, int yres,
			papi_resolution_unit_t units)
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
			char *name, int *x, int *y,
			papi_resolution_unit_t *units)
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

/*
 * Description: The given string contains one or more attributes, in the
 *	      following form:
 *		  "aaaa=true bbbbb=1 ccccc=abcd"
 *	      extract the next attribute from that string; the 'next'
 *	      parameter should be set to zero to extract the first attribute
 *	      in the string.
 *
 */

static char *
_getNextAttr(char *string, int *next)

{
	char *result = NULL;
	char *start = (char *)string + *next;
	char *nl = NULL;
	char *sp = NULL;
	char *tab = NULL;
	char *val = NULL;
	int len = 0;

	if ((string != NULL) && (*start != '\0')) {
		while ((*start == ' ') || (*start == '\t') || (*start == '\n'))
		{
			start++;
		}
		nl = strchr(start, '\n');
		sp = strchr(start, ' ');
		tab = strchr(start, '\t');

		val = strchr(start, '=');

		if ((val != NULL) && ((val[1] == '"') || (val[1] == '\''))) {
			val = strchr(&val[2], val[1]);
			if (val != NULL) {
				nl = strchr(&val[1], '\n');
				sp = strchr(&val[1], ' ');
				tab = strchr(&val[1], '\t');
			}
		}

		if ((nl != NULL) &&
		    ((sp == NULL) || ((sp != NULL) && (nl < sp))) &&
		    ((tab == NULL) || ((tab != NULL) && (nl < tab)))) {
			len = nl-start;
		} else if ((sp != NULL) && (tab != NULL) && (sp > tab)) {
			len = tab-start;
		} else if ((sp != NULL) && (sp != NULL)) {
			len = sp-start;
		} else if ((tab != NULL) && (tab != NULL)) {
			len = tab-start;
		}

		if (len == 0) {
			len = strlen(start);
		}

		if (len > 0) {
			result = (char *)malloc(len+1);
			if (result != NULL) {
				strncpy(result, start, len);
				result[len] = '\0';
				*next = (start-string)+len;
			}
		}
	}

	return (result);
} /* _getNextAttr() */


/*
 * Description: Parse the given attribute string value and transform it into
 *	      the papi_attribute_value_t in the papi_attribute_t structure.
 *
 */

static papi_status_t
_parseAttrValue(char *value, papi_attribute_t *attr)

{
	papi_status_t result = PAPI_OK;
	int len = 0;
	int i = 0;
	char *papiString = NULL;
	char *tmp1 = NULL;
	char *tmp2 = NULL;
	char *tmp3 = NULL;
	papi_attribute_value_t **avalues = NULL;

	avalues = malloc(sizeof (papi_attribute_value_t *) * 2);
	if (avalues == NULL) {
		result = PAPI_TEMPORARY_ERROR;
		return (result);
	}
	avalues[0] = malloc(sizeof (papi_attribute_value_t));
	avalues[1] = NULL;
	if (avalues[0] == NULL) {
		free(avalues);
		result = PAPI_TEMPORARY_ERROR;
		return (result);
	}


/*
 * TODO - need to sort out 'resolution', 'dateandtime' & 'collection' values
 */
	if ((value != NULL) && (strlen(value) > 0) && (attr != NULL)) {

		len = strlen(value);
		if ((len >= 2) && (((value[0] == '"') &&
				(value[len-1] == '"')) || ((value[0] == '\'') &&
				(value[len-1] == '\'')))) {
			/* string value */
			attr->type = PAPI_STRING;

			papiString = strdup(value+1);
			if (papiString != NULL) {
				papiString[strlen(papiString)-1] = '\0';
				avalues[0]->string = papiString;
			} else {
				result = PAPI_TEMPORARY_ERROR;
			}
		} else if ((strcasecmp(value, "true") == 0) ||
		    (strcasecmp(value, "YES") == 0)) {
			/* boolean = true */
			attr->type = PAPI_BOOLEAN;
			avalues[0]->boolean = PAPI_TRUE;
		} else if ((strcasecmp(value, "false") == 0) ||
		    (strcasecmp(value, "NO") == 0)) {
			/* boolean = false */
			attr->type = PAPI_BOOLEAN;
			avalues[0]->boolean = PAPI_FALSE;
		} else {
			/* is value an integer or a range ? */

			i = 0;
			attr->type = PAPI_INTEGER;
			tmp1 = strdup(value);
			while (((value[i] >= '0') && (value[i] <= '9')) ||
					(value[i] == '-')) {
				if (value[i] == '-') {
					tmp1[i] = '\0';
					tmp2 = &tmp1[i+1];
					attr->type = PAPI_RANGE;
				}

				i++;
			}

			if (strlen(value) == i) {
				if (attr->type == PAPI_RANGE) {
					avalues[0]->range.lower = atoi(tmp1);
					avalues[0]->range.upper = atoi(tmp2);
				} else {
					avalues[0]->integer = atoi(value);
				}
			} else {
				/* is value a resolution ? */
				i = 0;
				attr->type = PAPI_INTEGER;
				tmp1 = strdup(value);
				while (((value[i] >= '0') &&
					(value[i] <= '9')) ||
					(value[i] == 'x')) {
					if (value[i] == 'x') {
						tmp1[i] = '\0';
						if (attr->type == PAPI_INTEGER)
						{
							tmp2 = &tmp1[i+1];
							attr->type =
								PAPI_RESOLUTION;
						} else {
							tmp3 = &tmp1[i+1];
						}
					}

					i++;
				}

				if (strlen(value) == i) {
					if (attr->type == PAPI_RESOLUTION) {
						avalues[0]->resolution.xres =
								atoi(tmp1);
						avalues[0]->resolution.yres =
								atoi(tmp2);
						if (tmp3 != NULL) {
							avalues[0]->
							resolution.units =
								atoi(tmp3);
						} else {
							avalues[0]->
							resolution.units = 0;
						}
					}
				}

				if (attr->type != PAPI_RESOLUTION) {
					attr->type = PAPI_STRING;
					avalues[0]->string = strdup(value);
					if (avalues[0]->string == NULL) {
						result = PAPI_TEMPORARY_ERROR;
					}
				}
			}
			free(tmp1);
		}

	} else {
		result = PAPI_BAD_ARGUMENT;
	}

	if (result != PAPI_OK) {
		i = 0;
		while (avalues[i] != NULL) {
			free(avalues[i]);
			i++;
		}
		free(avalues);
	} else {
		attr->values = avalues;
	}

	return (result);
} /* _parseAttrValue() */


/*
 * Description: Parse the given attribute string and transform it into the
 *	      papi_attribute_t structure.
 *
 */

static papi_status_t
_parseAttributeString(char *attrString, papi_attribute_t *attr)

{
	papi_status_t result = PAPI_OK;
	char *string = NULL;
	char *p = NULL;
	papi_attribute_value_t **avalues = NULL;

	if ((attrString != NULL) && (strlen(attrString) >= 3) &&
	    (attr != NULL)) {
		attr->name = NULL;
		string = strdup(attrString);
		if (string != NULL) {
			p = strchr(string, '=');
			if (p != NULL) {
				*p = '\0';
				attr->name = string;
				p++;  /* pointer to value */

				result = _parseAttrValue(p, attr);
			} else {
				char value;
				/* boolean - no value so assume 'true' */
				if (strncasecmp(string, "no", 2) == 0) {
					string += 2;
					value = PAPI_FALSE;
				} else
					value = PAPI_TRUE;

				attr->name = string;
				attr->type = PAPI_BOOLEAN;

				avalues = malloc(
					sizeof (papi_attribute_value_t *) * 2);
				if (avalues == NULL) {
					result = PAPI_TEMPORARY_ERROR;
				} else {
					avalues[0] = malloc(
					sizeof (papi_attribute_value_t));
					avalues[1] = NULL;
					if (avalues[0] == NULL) {
						free(avalues);
						result = PAPI_TEMPORARY_ERROR;
					} else {
						avalues[0]->boolean = value;
						attr->values = avalues;
					}
				}
			}
		}
	} else {
		result = PAPI_BAD_ARGUMENT;
	}

	return (result);
} /* _parseAttributeString() */


papi_status_t
papiAttributeListFromString(papi_attribute_t ***attrs,
		int flags, char *string)
{
	papi_status_t result = PAPI_OK;
	int	   next = 0;
	char	 *attrString = NULL;
	papi_attribute_t attr;

	if ((attrs != NULL) && (string != NULL) &&
	    ((flags & ~(PAPI_ATTR_APPEND+PAPI_ATTR_REPLACE+PAPI_ATTR_EXCL))
			== 0)) {
		attrString = _getNextAttr(string, &next);
		while ((result == PAPI_OK) && (attrString != NULL)) {
			result = _parseAttributeString(attrString, &attr);
			if ((result == PAPI_OK) && (attr.name != NULL)) {
				/* add this attribute to the list */
				if ((attr.values != NULL) &&
				    (attr.values[0] != NULL)) {
					result = papiAttributeListAddValue(
							attrs, PAPI_ATTR_APPEND,
							attr.name, attr.type,
							attr.values[0]);
					free(attr.values[0]);
					free(attr.values);
				} else {
					result = PAPI_TEMPORARY_ERROR;
				}
			}
			free(attrString);

			attrString = _getNextAttr(string, &next);
		}
	}
	else
	{
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

	strlcat(buffer, attribute->name, buflen);
	strlcat(buffer, "=", buflen);

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
			rc = strlcat(buffer, (values[i]->boolean ? "true" :
							"false"), buflen);
			break;
		case PAPI_RANGE: {
			char string[24];

			snprintf(string, sizeof (string), "%d-%d",
				values[i]->range.lower, values[i]->range.upper);
			rc = strlcat(buffer, string, buflen);
			}
			break;
		case PAPI_RESOLUTION: {
			char string[24];

			snprintf(string, sizeof (string), "%dx%ddp%c",
				values[i]->resolution.xres,
				values[i]->resolution.yres,
				(values[i]->resolution.units == PAPI_RES_PER_CM
							? 'c' : 'i'));
			rc = strlcat(buffer, string, buflen);
			}
			break;
		case PAPI_DATETIME: {
			struct tm *tm = localtime(&values[i]->datetime);

			if (tm != NULL) {
				char string[64];

				strftime(string, sizeof (string), "%C", tm);
				rc = strlcat(buffer, string, buflen);
			}}
			break;
		case PAPI_COLLECTION: {
			char *string = alloca(buflen);
#ifdef DEBUG
			char prefix[256];

			snprintf(prefix, sizeof (prefix), "%s  %s(%d)  ", delim,
					attribute->name, i);

			papiAttributeListToString(values[i]->collection,
					prefix, string, buflen);
#else
			papiAttributeListToString(values[i]->collection,
					delim, string, buflen);
#endif
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

#ifdef DEBUG
	strlcat(buffer, delim, buflen);
#endif
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
					attribute->name, attribute->type,
					attribute->values[i]);
	     ((status == PAPI_OK) && (attribute->values[i] != NULL));
	     status = papiAttributeListAddValue(list, PAPI_ATTR_APPEND,
					attribute->name, attribute->type,
					attribute->values[i]))
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
