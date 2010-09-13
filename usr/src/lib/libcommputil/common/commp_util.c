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

/*
 * Helper functions to skip white spaces, find tokens, find separators and free
 * memory.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "commp_util.h"


/*
 * Skip to the next non-whitespace
 */
int
commp_skip_white_space(const char **begin, const char *end)
{
	while (*begin < end) {
		if (!isspace(**begin))
			return (0);
		(*begin)++;
	}
	return (1);
}

/*
 * Finds the token in the char buffer. *current will be pointing to the
 * token when function returns. If the char buffer has leading token,
 * it returns 1.
 */
int
commp_find_token(const char **begin, const char **current,  const char *end,
    char token, boolean_t last)
{
	*current = *begin;
	while (*current < end) {
		if (!last && (**current == token))
			break;
		else if (isspace(**current))
			return (1);
		(*current)++;
	}
	/* Checks for leading white space */
	if (*current == *begin)
		return (1);
	else
		return (0);
}

/*
 * atoi function
 */
int
commp_atoi(const char *begin, const char *end, int *num)
{
	boolean_t	num_found = B_FALSE;

	*num = 0;
	while (begin < end) {
		if (isdigit(*begin)) {
			*num = (*num * 10) + (*begin - '0');
			num_found = B_TRUE;
			begin++;
		} else {
			break;
		}
	}
	if (!num_found || (begin != end))
		return (EINVAL);
	return (0);
}

/*
 * Given a string converts it to unsigned long long int.
 */
int
commp_strtoull(const char *begin, const char *end, uint64_t *num)
{
	boolean_t	num_found = B_FALSE;

	*num = 0;
	while (begin < end) {
		if (isdigit(*begin)) {
			*num = (*num * 10) + (*begin - '0');
			num_found = B_TRUE;
			begin++;
		} else {
			break;
		}
	}
	if (!num_found || (begin != end))
		return (EINVAL);
	return (0);
}

/*
 * Given a string converts it to unsigned byte
 */
int
commp_strtoub(const char *begin, const char *end, uint8_t *num)
{
	boolean_t	num_found = B_FALSE;

	*num = 0;
	while (begin < end) {
		if (isdigit(*begin)) {
			*num = (*num * 10) + (*begin - '0');
			num_found = B_TRUE;
			begin++;
		} else {
			break;
		}
	}
	if (!num_found || (begin != end))
		return (EINVAL);
	return (0);
}

/*
 * Given a string converts it to unsigned int
 */
int
commp_atoui(const char *begin, const char *end, uint_t *num)
{
	boolean_t	num_found = B_FALSE;

	*num = 0;
	while (begin < end) {
		if (isdigit(*begin)) {
			*num = (*num * 10) + (*begin - '0');
			num_found = B_TRUE;
			begin++;
		} else {
			break;
		}
	}
	if (!num_found || (begin != end))
		return (EINVAL);
	return (0);
}

/*
 * allocates memory and copies string to new memory
 */
int
commp_add_str(char **dest, const char *src, int len)
{
	if (len == 0)
		return (EINVAL);
	(*dest) = calloc(1, len + 1);
	if (*dest == NULL)
		return (ENOMEM);
	(void) strncpy(*dest, src, len);
	return (0);
}

/*
 * This function converts strings like "5d" to equivalent time in secs.
 * For eg. 1h = 3600, 10d = 86400
 */
int
commp_time_to_secs(const char *begin, const char *end, uint64_t *num)
{
	uint_t		factor = 0;

	if (!isdigit(*(end - 1))) {
		switch (*(end - 1)) {
			case 'd':
				factor = COMMP_SECS_IN_DAY;
				break;
			case 'h':
				factor = COMMP_SECS_IN_HOUR;
				break;
			case 'm':
				factor = COMMP_SECS_IN_MIN;
				break;
			case 's':
				factor = 1;
				break;
			default:
				return (EINVAL);
		}
		--end;
	}
	if (commp_strtoull(begin, end, num) != 0)
		return (EINVAL);
	if (factor != 0)
		(*num) = (*num) * factor;
	return (0);
}
