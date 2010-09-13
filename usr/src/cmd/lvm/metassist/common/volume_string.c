/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "volume_string.h"

#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "volume_error.h"
#include "volume_output.h"

/*
 * ******************************************************************
 *
 * Function prototypes
 *
 * ******************************************************************
 */

static void *append_to_pointer_array(void **array, void *pointer);

/*
 * ******************************************************************
 *
 * Data
 *
 * ******************************************************************
 */

/* All-inclusive valid size units */
units_t universal_units[] = {
	{"BLOCKS", BYTES_PER_BLOCK},
	{"KB", BYTES_PER_KILOBYTE},
	{"MB", BYTES_PER_MEGABYTE},
	{"GB", BYTES_PER_GIGABYTE},
	{"TB", BYTES_PER_TERABYTE},
	{NULL, 0}
};

/*
 * ******************************************************************
 *
 * External functions
 *
 * ******************************************************************
 */

/*
 * Concatenates a list of strings.  The result must be free()d.
 *
 * @param       numargs
 *              The number of strings to concatenate.
 *
 * @param       ...
 *              The strings (type char *) to concatenate.
 *
 * @return      the concatenated string
 *              if succesful
 *
 * @return      NULL
 *              if memory could not be allocated
 */
char *
stralloccat(
	int numargs,
	...)
{
	va_list vl;
	int i;
	int len = 1;
	char *cat;

	/* Determine length of concatenated string */
	va_start(vl, numargs);
	for (i = 0; i < numargs; i++) {
	    char *str = va_arg(vl, char *);
	    if (str != NULL) {
		len += strlen(str);
	    }
	}
	va_end(vl);

	/* Allocate memory for concatenation plus a trailing NULL */
	cat = (char *)calloc(1, len * sizeof (char));

	if (cat == NULL) {
	    return (NULL);
	}

	/* Concatenate strings */
	va_start(vl, numargs);
	for (i = 0; i < numargs; i++) {
	    char *str = va_arg(vl, char *);
	    if (str != NULL) {
		strcat(cat, str);
	    }
	}
	va_end(vl);

	return (cat);
}

/*
 * Convert the given string to a uint16_t, verifying that the value
 * does not exceed the lower or upper bounds of a uint16_t.
 *
 * @param       str
 *              the string to convert
 *
 * @param       num
 *              the addr of the uint16_t
 *
 * @return      0
 *              if the given string was converted to a uint16_t
 *
 * @return      -1
 *              if the string could could not be converted to a number
 *
 * @return      -2
 *              if the converted number exceeds the lower or upper
 *              bounds of a uint16_t
 */
int
str_to_uint16(
	char *str,
	uint16_t *num)
{
	long long lnum;
	int error = 0;

	/* Convert string to long long */
	if (sscanf(str, "%lld", &lnum) != 1) {
	    error = -1;
	} else {

		/*
		 * Verify that the long long value does not exceed the
		 * lower or upper bounds of a uint16_t
		 */

	    /* Maximum value of uint16_t */
	    uint16_t max = (uint16_t)~0ULL;

	    if (lnum < 0 || lnum > max) {
		error = -2;
	    } else {
		*num = lnum;
	    }
	}

	return (error);
}

/*
 * Converts the given long long into a string.  This string must be
 * freed.
 *
 * @param       num
 *              the long long to convert
 *
 * @param       str
 *              the addr of the string
 *
 * @return      0
 *              if successful
 *
 * @return      ENOMEM
 *              if the physical limits of the system are exceeded by
 *              size bytes of memory which cannot be allocated
 *
 * @return      EAGAIN
 *              if there is not enough memory available to allocate
 *              size bytes of memory
 */
int
ll_to_str(
	long long num,
	char **str)
{
	int error = 0;

	/* Allocate memory for the string */
	if ((*str = calloc(1, LONG_LONG_STR_SIZE * sizeof (char))) == NULL) {
	    error = errno;
	} else {
	    /* Convert the integer to a string */
	    snprintf(*str, LONG_LONG_STR_SIZE, "%lld", num);
	}

	return (error);
}

/*
 * Convert a size specification to bytes.
 *
 * @param       str
 *              a size specification strings of the form
 *              <value><units>, where valid <units> are specified by
 *              the units argument and <value> is the (floating-point)
 *              multiplier of the units
 *
 * @param       bytes
 *              RETURN: the result of converting the given size string
 *              to bytes
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
sizestr_to_bytes(
	char *str,
	uint64_t *bytes,
	units_t units[])
{
	char *unit_str;
	long double d;
	int error = 0;
	int i;

	/* Convert <value> string to double */
	if ((d = strtod(str, &unit_str)) == 0) {
	    volume_set_error(gettext("invalid size string: %s"), str);
	    error = -1;
	} else {

	    /* Trim leading white space */
	    while (isspace(*unit_str) != 0) {
		++unit_str;
	    }

	    /* Convert to bytes based on <units> */
	    for (i = 0; units[i].unit_str != NULL; i++) {
		if (strcasecmp(unit_str, units[i].unit_str) == 0) {
		    d *= units[i].bytes_per_unit;
		    break;
		}
	    }

	    /* Was a valid unit string found? */
	    if (units[i].unit_str == NULL) {
		volume_set_error(
		    gettext("missing or invalid units indicator in size: %s"),
		    str);
		error = -1;
	    }
	}

	if (error) {
	    *bytes = 0;
	} else {
	    *bytes = (uint64_t)d;
	    oprintf(OUTPUT_DEBUG,
		gettext("converted \"%s\" to %llu bytes\n"), str, *bytes);
	}

	return (error);
}

/*
 * Convert bytes to a size specification string.
 *
 * @param       bytes
 *              the number of bytes
 *
 * @param       str
 *              RETURN: a size specification strings of the form
 *              <value><units>, where valid <units> are specified by
 *              the units argument and <value> is the (floating-point)
 *              multiplier of the units.  This string must be freed.
 *
 * @return      0
 *              if successful
 *
 * @return      non-zero
 *              if an error occurred.  Use get_error_string() to
 *              retrieve the associated error message.
 */
int
bytes_to_sizestr(
	uint64_t bytes,
	char **str,
	units_t units[],
	boolean_t round)
{
	int i, len, error = 0;
	double value;
	const char *format;
	units_t use_units = units[0];

	/* Determine the units to use */
	for (i = 0; units[i].unit_str != NULL; i++) {
	    if (bytes >= units[i].bytes_per_unit) {
		use_units = units[i];
	    }
	}

	value = ((long double)bytes / use_units.bytes_per_unit);

	/* Length of string plus trailing NULL */
	len = LONG_LONG_STR_SIZE + strlen(use_units.unit_str) + 1;

	if (round) {
	    value = floor(value + 0.5F);
	    format = "%.0f%s";
	} else {
	    format = "%.2f%s";
	}

	/* Append units to string */
	*str = calloc(1, len * sizeof (char));
	if (*str == NULL) {
	    error = errno;
	} else {
	    snprintf(*str, len, format, value, use_units.unit_str);
	}

	return (error);
}

/*
 * Appends a copy of the given string to the given string array,
 * ensuring that the last element in the array is NULL.  This array
 * must be freed via free_string_array.
 *
 * Note when an error occurs and NULL is returned, array is not freed.
 * Subsequently callers should save a pointer to the original array
 * until success is verified.
 *
 * @param       array
 *              the array to append to, or NULL to create a new array
 *
 * @param       str
 *              the string to copy and add to the array
 *
 * @return      a pointer to the realloc'd (and possibly moved) array
 *              if succesful
 *
 * @return      NULL
 *              if unsuccesful
 */
char **
append_to_string_array(
	char **array,
	char *str)
{
	char *copy = strdup(str);

	if (copy == NULL) {
	    return (NULL);
	}

	return ((char **)append_to_pointer_array((void **)array, copy));
}

/*
 * Frees each element of the given string array, then frees the array
 * itself.
 *
 * @param       array
 *              a NULL-terminated string array
 */
void
free_string_array(
	char **array)
{
	int i;

	/* Free each available element */
	for (i = 0; array[i] != NULL; i++) {
	    free(array[i]);
	}

	/* Free the array itself */
	free((void *)array);
}

/*
 * ******************************************************************
 *
 * Static functions
 *
 * ******************************************************************
 */

/*
 * Appends the given pointer to the given pointer array, ensuring that
 * the last element in the array is NULL.
 *
 * Note when an error occurs and NULL is returned, array is not freed.
 * Subsequently callers should save a pointer to the original array
 * until success is verified.
 *
 * @param       array
 *              the array to append to, or NULL to create a new array
 *
 * @param       pointer
 *              the pointer to add to the array
 *
 * @return      a pointer to the realloc'd (and possibly moved) array
 *              if succesful
 *
 * @return      NULL
 *              if unsuccesful
 */
static void *
append_to_pointer_array(
	void **array,
	void *pointer)
{
	void **newarray = NULL;
	int i = 0;

	if (array != NULL) {
	    /* Count the elements currently in the array */
	    for (i = 0; array[i] != NULL; ++i);
	}

	/* realloc, adding a slot for the new pointer */
	newarray = (void **)realloc(array, (i + 2) * sizeof (*array));

	if (newarray != NULL) {
	    /* Append pointer and terminal NULL */
	    newarray[i] = pointer;
	    newarray[i+1] = NULL;
	}

	return (newarray);
}
