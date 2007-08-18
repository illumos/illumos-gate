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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <limits.h>
#include "utils.h"

static char PNAME_FMT[] = "%s: ";
static char ERRNO_FMT[] = ": %s\n";
static char EOL_FMT[] = "\n";

static char *pname;

char *
setprogname(char *arg0)
{
	char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;
	pname = p;
	return (pname);
}

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	int err = errno;
	va_list alist;
	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		if (err)
			(void) fprintf(stderr,
			    gettext(ERRNO_FMT), strerror(err));
		else
			(void) fprintf(stderr, gettext(EOL_FMT));


}

static char *__metric_modifiers[] = { "K", "M", "G", "T", "P", "E", NULL };
static uint64_t __metric_scales[] = {
    1000LLU,
    1000LLU * 1000,
    1000LLU * 1000 * 1000,
    1000LLU * 1000 * 1000 * 1000,
    1000LLU * 1000 * 1000 * 1000 * 1000,
    1000LLU * 1000 * 1000 * 1000 * 1000 * 1000
};
static scale_t __metric_scale = { __metric_modifiers, __metric_scales };

static char *__binary_modifiers[] = {"K", "M", "G", "T", "P", "E", NULL};
static uint64_t __binary_scales[] = {
    1024LLU,
    1024LLU * 1024,
    1024LLU * 1024 * 1024,
    1024LLU * 1024 * 1024 * 1024,
    1024LLU * 1024 * 1024 * 1024 * 1024,
    1024LLU * 1024 * 1024 * 1024 * 1024 * 1024
};
static scale_t __binary_scale = { __binary_modifiers, __binary_scales };

scale_t *scale_metric = &__metric_scale;
scale_t *scale_binary = &__binary_scale;

int
scaledtouint64(char *scaledin,
    uint64_t *uint64out,
    int *widthout, char **modifierout, char **unitout,
    scale_t *scale, char *unit, int flags) {

	double result;
	double value;
	int index = 0;
	uint64_t multiplier = 1;
	char string[SCALED_STRLEN];
	char *endptr;
	int cmp;
	int hasmodifier = 0;
	char **modifiers = scale->modifers;
	uint64_t *scales = scale->scales;

	if (modifierout)
		*modifierout = NULL;
	if (unitout)
		*unitout = NULL;

	/*
	 * first check for hex value, which cannot be scaled, as
	 * hex letters cannot be disserned from modifier or unit letters
	 */
	if ((strncmp("0x", scaledin, 2) == 0) ||
	    (strncmp("0X", scaledin, 2) == 0)) {

		/* unit cannot be required on hex values */
		if ((unit && *unit != '\0') &&
		    !(flags & SCALED_UNIT_OPTIONAL_FLAG))
			return (SCALED_INVALID_UNIT);

		errno = 0;
		*uint64out = strtoull(scaledin, &endptr, 16);
		if (errno) {
			if (errno == ERANGE)
				return (SCALED_OVERFLOW);
			else
				return (SCALED_INVALID_NUMBER);
		}
		if (*endptr != '\0')
			return (SCALED_INVALID_NUMBER);

		/* compute width of decimal equivalent */
		if (widthout) {
			(void) snprintf(
			    string, SCALED_STRLEN, "%llu", *uint64out);
			*widthout = strlen(string);
		}
		return (0);
	}

	/* scan out numeric value */
	errno = 0;
	value = strtod(scaledin, &endptr);
	if (errno) {
		if (errno == ERANGE)
			return (SCALED_OVERFLOW);
		else
			return (SCALED_INVALID_NUMBER);

	}
	if (endptr == scaledin)
		return (SCALED_INVALID_NUMBER);

	/* no negative values */
	if (strchr(scaledin, '-'))
		return (SCALED_INVALID_NUMBER);
	if (value < 0.0)
		return (SCALED_INVALID_NUMBER);


	/* compute width of number string */
	if (widthout)
		*widthout = (int)(endptr - scaledin);

	/* check possible modifier */
	if (*endptr != '\0') {
		index = 0;
		while (modifiers[index] != NULL) {
			if (flags & SCALED_MODIFIER_CASE_INSENSITIVE_FLAG)
				cmp = strncasecmp(modifiers[index], endptr,
				    strlen(modifiers[index]));
			else
				cmp = strncmp(modifiers[index], endptr,
				    strlen(modifiers[index]));

			if (cmp == 0) {
				if (modifierout)
					*modifierout = modifiers[index];
				endptr += strlen(modifiers[index]);
				multiplier = scales[index];
				result = value * multiplier;
				if (result > UINT64_MAX)
					return (SCALED_OVERFLOW);

				*uint64out = (uint64_t)result;
				hasmodifier = 1;
				break;
			}
			index++;
		}
	}
	/* if there is no modifier, value must be an integer */
	if (!hasmodifier) {
		errno = 0;
		*uint64out = strtoull(scaledin, &endptr, 0);
		if (errno) {
			if (errno == ERANGE)
				return (SCALED_OVERFLOW);
			else
				return (SCALED_INVALID_NUMBER);
		}
		if (endptr == scaledin)
			return (SCALED_INVALID_NUMBER);
	}

	/* if unit is present when no unit is allowed, fail */
	if ((unit == NULL || *unit == '\0') && (*endptr != '\0'))
		return (SCALED_INVALID_UNIT);

	/* check for missing unit when unit is required */
	if ((unit && *unit != '\0') &&
	    !(flags & SCALED_UNIT_OPTIONAL_FLAG) &&
	    (*endptr == '\0'))
		return (SCALED_INVALID_UNIT);

	/* validate unit */
	if (unit && *unit != '\0') {

		/* allow for missing unit if it is optional */
		if ((flags & SCALED_UNIT_OPTIONAL_FLAG) &&
		    (*endptr == '\0'))
			return (0);

		if (flags & SCALED_UNIT_CASE_INSENSITIVE_FLAG)
			cmp = strncasecmp(unit, endptr, strlen(unit));
		else
			cmp = strncmp(unit, endptr, strlen(unit));

		if (cmp != 0)
			return (SCALED_INVALID_UNIT);

		if (*(endptr + strlen(unit)) != '\0')
			return (SCALED_INVALID_UNIT);

		if (unitout)
			*unitout = unit;
	}
	return (0);
}


int
uint64toscaled(uint64_t uint64in, int widthin, char *maxmodifierin,
    char *scaledout, int *widthout, char **modifierout,
    scale_t *scale, char *unit, int flags) {

	int index = 0;
	int count;
	int width;
	int decimals = 0;
	char string[SCALED_STRLEN];
	double value;
	char **modifiers = scale->modifers;
	uint64_t *scales = scale->scales;

	/* don't scale if there is no reason to */
	if (uint64in < scales[0] || maxmodifierin == NULL) {
		if (flags & SCALED_PAD_WIDTH_FLAG)
			width = widthin;
		else
			width = 0;

		(void) snprintf(string, SCALED_STRLEN, "%%%dllu", width);
		/* LINTED */
		count = snprintf(scaledout, SCALED_STRLEN, string, uint64in);
		if (unit && *unit != '\0')
			(void) strcat(scaledout, unit);

		if (widthout)
			*widthout = count;

		if (modifierout)
			*modifierout = NULL;

		return (0);
	}

	for (index = 0; modifiers[index + 1] != NULL; index++) {

		if (uint64in >= scales[index] &&
		    uint64in < scales[index + 1])
			break;

		if ((strncmp(modifiers[index], maxmodifierin,
		    strlen(modifiers[index])) == 0) &&
		    (strlen(modifiers[index]) == strlen(maxmodifierin)))
			break;

	}

	value = ((double)(uint64in)) / scales[index];
	if (modifierout)
		*modifierout = modifiers[index];

	count = snprintf(string, SCALED_STRLEN, "%0.0lf", value);
	while (count < widthin) {
		decimals++;
		(void) snprintf(string, SCALED_STRLEN, "%%0.%dlf", decimals);
		/* LINTED */
		count = snprintf(scaledout, SCALED_STRLEN, string, value);

		/* reduce decimal places if we've overshot the desired width */
		if (count > widthin) {
			decimals--;
			break;
		}
	}

	if (flags & SCALED_PAD_WIDTH_FLAG)
		width = widthin;
	else
		width = 0;

	(void) snprintf(string, SCALED_STRLEN, "%%%d.%dlf", width, decimals);
	/* LINTED */
	count = snprintf(scaledout, SCALED_STRLEN, string, value);

	(void) strcat(scaledout, modifiers[index]);

	if (unit && *unit != '\0')
		(void) strcat(scaledout, unit);

	if (widthout)
		*widthout = count;

	return (0);
}

int
scaledtoscaled(char *scaledin, int widthin, char *maxmodifierin,
    char *scaledout, int *widthout, char **modifierout,
    scale_t *scale, char *unit, int flags) {

	int ret;
	uint64_t val;

	ret = scaledtouint64(scaledin, &val, NULL, NULL, NULL,
	    scale, unit, flags);
	if (ret)
		return (ret);

	ret = uint64toscaled(val, widthin, maxmodifierin,
	    scaledout, widthout, modifierout,
	    scale, unit, flags);

	return (ret);
}

int
scaledeqscaled(char *scaled1, char *scaled2,
    scale_t *scale, char *unit, int flags) {

	int ret;
	uint64_t uint64;
	char *modifier1;
	char *modifier2;
	char *modifier = NULL;
	int i;
	int width;
	int width1;
	int width2;
	char scaledA[SCALED_STRLEN];
	char scaledB[SCALED_STRLEN];
	char **modifiers = scale->modifers;

	/*
	 * remove padding flag, so strings to compare will not have
	 * whitespace
	 */
	flags = flags & (~SCALED_PAD_WIDTH_FLAG);

	/* determine each number's width and modifier */
	ret = scaledtouint64(scaled1, &uint64, &width1, &modifier1, NULL,
	    scale, unit, flags);
	if (ret)
		return (0);

	ret = scaledtouint64(scaled2, &uint64, &width2, &modifier2, NULL,
	    scale, unit, flags);
	if (ret)
		return (0);

	/*
	 * determine the width and modifier to use for comparison.
	 * Use widest width and smallest modifier.
	 * Rescale to new width and modifier
	 */

	if (modifier1 == NULL || modifier2 == NULL)
		modifier = NULL;
	else {
		for (i = 0; modifiers[i] != NULL; i++) {

			if (strcmp(modifier1, modifiers[i]) == 0) {
				modifier = modifiers[i];
				break;
			}
			if (strcmp(modifier2, modifiers[i]) == 0) {
				modifier = modifiers[i];
				break;
			}
		}
	}
	width = 0;
	if (width1 > width)
		width = width1;
	if (width2 > width)
		width = width2;

	/*
	 * Convert first number to width and modifier.
	 * This is done for the following reasons:
	 *	1. In case first number is hecadecimal.  This will convert
	 *	   it to decimal
	 *	2. In case the first number has < the minimum number of
	 *	   columns.
	 *	3. The first number is missing an optional unit string.
	 *	4. Fix casing of modifier and unit.
	 */

	ret = scaledtoscaled(scaled1, width, modifier,
	    scaledA, NULL, NULL, scale, unit, flags);
	if (ret)
		return (0);

	/* convert second number to width and modifier matching first number */
	ret = scaledtoscaled(scaled2, width, modifier,
	    scaledB, NULL, NULL, scale, unit, flags);
	if (ret)
		return (0);

	/* numbers are equal if strings match */
	return ((strncmp(scaledA, scaledB, strlen(scaledA)) == 0) &&
	    (strlen(scaledA) == strlen(scaledB)));

}

int
scaledequint64(char *scaled, uint64_t uint64, int minwidth,
    scale_t *scale, char *unit, int flags) {

	int ret;
	uint64_t tmpuint64;
	char *modifier;
	int width;

	char scaledA[SCALED_STRLEN];
	char scaledB[SCALED_STRLEN];

	/* determine for number's width and modifier */
	ret = scaledtouint64(scaled, &tmpuint64, &width, &modifier, NULL,
	    scale, unit, flags);
	if (ret)
		return (0);

	if (width < minwidth)
		width = minwidth;

	/*
	 * Convert first number to width and modifier.
	 * This is done for the following reasons:
	 *	1. In case first number is hecadecimal.  This will convert
	 *	   it to decimal
	 *	2. In case the first number has < the minimum number of
	 *	   columns.
	 *	3. The first number is missing an optional unit string.
	 *	4. Fix casing of modifier and unit.
	 */

	ret = scaledtoscaled(scaled, width, modifier,
	    scaledA, NULL, NULL, scale, unit, flags);
	if (ret)
		return (0);

	/* convert second number to width and modifier matching first number */
	ret = uint64toscaled(uint64, width, modifier,
	    scaledB, NULL, NULL, scale, unit, flags);
	if (ret)
		return (0);

	/* numbers are equal if strings match */
	return ((strncmp(scaledA, scaledB, strlen(scaledA)) == 0) &&
	    (strlen(scaledA) == strlen(scaledB)));
}
