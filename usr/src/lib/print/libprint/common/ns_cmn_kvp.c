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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>

#include <ns.h>
#include <list.h>

/*
 *	Commonly Used routines...
 */

/*
 * FUNCTION:
 *	kvp_create(const char *key, const void *value)
 * INPUT(S):
 *	const char *key
 *		- key for key/value pair
 *	const void *value
 *		- value for key/value pair
 * OUTPUT(S):
 *	ns_kvp_t * (return value)
 *		- pointer to structure containing the key/value pair
 * DESCRIPTION:
 */
ns_kvp_t *
ns_kvp_create(const char *key, const char *value)
{
	ns_kvp_t *kvp;

	if ((kvp = calloc(1, sizeof (*kvp))) != NULL) {
		kvp->key = strdup(key);
		kvp->value = (char *)value;
	}
	return (kvp);
}

int
ns_kvp_destroy(void *arg, va_list arg1 __unused)
{
	ns_kvp_t *kvp = arg;

	if (kvp != NULL) {
		if (kvp->key != NULL)
			free(kvp->key);
		if (kvp->value != NULL)
			free(kvp->value);
		free(kvp);
	}
	return (0);
}




/*
 * FUNCTION:
 *	ns_kvp_match_key(const ns_kvp_t *kvp, const char *key)
 * INPUT(S):
 *	const ns_kvp_t *kvp
 *		- key/value pair to check
 *	const char *key
 *		- key for matching
 * OUTPUT(S):
 *	int (return value)
 *		- 0 if matched
 * DESCRIPTION:
 */
static int
ns_kvp_match_key(const ns_kvp_t *kvp, char *key)
{
	if ((kvp != NULL) && (kvp->key != NULL) && (key != NULL))
		return (strcmp(kvp->key, key));
	return (-1);
}


/*
 * FUNCTION:
 *	ns_r_get_value(const char *key, const ns_printer_t *printer)
 * INPUT(S):
 *	const char *key
 *		- key for matching
 *	const ns_printer_t *printer
 *		- printer to glean this from
 * OUTPUT(S):
 *	char * (return value)
 *		- NULL, if not matched
 * DESCRIPTION:
 */
static void *
ns_r_get_value(const char *key, const ns_printer_t *printer, int level)
{
	ns_kvp_t *kvp, **attrs;

	if ((key == NULL) || (printer == NULL) ||
	    (printer->attributes == NULL))
		return (NULL);

	if (level++ == 16)
		return (NULL);

	/* find it right here */
	if ((kvp = list_locate((void **)printer->attributes,
	    (COMP_T)ns_kvp_match_key, (void *)key)) != NULL) {
		void *value = string_to_value(key, kvp->value);

		/* fill in an empty printer for a bsdaddr */
		if (strcmp(key, NS_KEY_BSDADDR) == 0) {
			ns_bsd_addr_t *addr = value;

			if (addr->printer == NULL)
				addr->printer = strdup(printer->name);
		}
		return (value);
	}

	/* find it in a child */
	for (attrs = printer->attributes; attrs != NULL && *attrs != NULL;
	    attrs++) {
		void *value = NULL;

		if ((strcmp((*attrs)->key, NS_KEY_ALL) == 0) ||
		    (strcmp((*attrs)->key, NS_KEY_GROUP) == 0)) {
			char **printers;

			for (printers = string_to_value((*attrs)->key,
			    (*attrs)->value);
			    printers != NULL && *printers != NULL; printers++) {
				ns_printer_t *printer =
				    ns_printer_get_name(*printers, NULL);

				value = ns_r_get_value(key, printer, level);
				if (value != NULL)
					return (value);
				ns_printer_destroy(printer);
			}
		} else if (strcmp((*attrs)->key, NS_KEY_LIST) == 0) {
			ns_printer_t **printers;

			for (printers = string_to_value((*attrs)->key,
			    (*attrs)->value);
			    printers != NULL && *printers != NULL; printers++) {
				value = ns_r_get_value(key, *printers, level);
				if (value != NULL)
					return (value);
			}
		} else if (strcmp((*attrs)->key, NS_KEY_USE) == 0) {
			char *string = NULL;
			ns_printer_t *printer =
			    ns_printer_get_name((*attrs)->value, NULL);
			value = ns_r_get_value(key, printer, level);
			if (value != NULL)
				string = value_to_string(string, value);
			if (string != NULL)
				value = string_to_value(key, string);
			ns_printer_destroy(printer);
		}

		if (value != NULL)
			return (value);
	}

	return (NULL);
}


/*
 * ns_get_value() gets the value of the passed in attribute from the passed
 * in printer structure.  The value is returned in a converted format.
 */
void *
ns_get_value(const char *key, const ns_printer_t *printer)
{
	return (ns_r_get_value(key, printer, 0));
}


/*
 * ns_get_value_string() gets the value of the key passed in from the
 * printer structure passed in.  The results is an ascii string.
 */
char *
ns_get_value_string(const char *key, const ns_printer_t *printer)
{
	return ((char *)value_to_string(key, ns_get_value(key, printer)));
}


/*
 * ns_set_value() sets the passed in kvp in the passed in printer structure,
 * This is done by converting the value to a string first.
 */
int
ns_set_value(const char *key, const void *value, ns_printer_t *printer)
{
	return (ns_set_value_from_string(key,
	    value_to_string(key, (void *)value), printer));
}


/*
 * ns_set_value_from_string() sets the passed in kvp in the passed in printer
 * structure.
 */
int
ns_set_value_from_string(const char *key, const char *string,
    ns_printer_t *printer)
{
	if (printer == NULL)
		return (-1);

	if (key == NULL) {
		list_iterate((void **)printer->attributes, ns_kvp_destroy);
	} else {
		ns_kvp_t *kvp;

		if (((kvp = list_locate((void **)printer->attributes,
		    (COMP_T)ns_kvp_match_key, (void *)key)) == NULL) &&
		    ((kvp = calloc(1, sizeof (*kvp))) != NULL)) {
			kvp->key = strdup(key);
			printer->attributes = (ns_kvp_t **)
			    list_append((void **)printer->attributes, kvp);
		}
		if (string != NULL)
			kvp->value = strdup(string);
		else
			kvp->value = NULL;
	}

	return (0);
}
