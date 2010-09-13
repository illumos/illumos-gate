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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2008 Denis Cheng
 */

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "filebench.h"
#include "utils.h"
#include "parsertypes.h"

/*
 * For now, just three routines: one to allocate a string in shared
 * memory, one to emulate a strlcpy() function and one to emulate a
 * strlcat() function, both the second and third only used in non
 * Solaris environments,
 *
 */


/*
 * Allocates space for a new string of the same length as
 * the supplied string "str". Copies the old string into
 * the new string and returns a pointer to the new string.
 * Returns NULL if memory allocation for the new string fails.
 */
char *
fb_stralloc(char *str)
{
	char *newstr;

	if ((newstr = malloc(strlen(str) + 1)) == NULL)
		return (NULL);
	(void) strcpy(newstr, str);
	return (newstr);
}

#ifndef sun

/*
 * Implements the strlcpy function when compilied for non Solaris
 * operating systems. On solaris the strlcpy() function is used
 * directly.
 */
size_t
fb_strlcpy(char *dst, const char *src, size_t dstsize)
{
	uint_t i;

	for (i = 0; i < (dstsize - 1); i++) {

		/* quit if at end of source string */
		if (src[i] == '\0')
			break;

		dst[i] = src[i];
	}

	/* set end of dst string to \0 */
	dst[i] = '\0';
	i++;

	return (i);
}

/*
 * Implements the strlcat function when compilied for non Solaris
 * operating systems. On solaris the strlcat() function is used
 * directly.
 */
size_t
fb_strlcat(char *dst, const char *src, size_t dstsize)
{
	uint_t i, j;

	/* find the end of the current destination string */
	for (i = 0; i < (dstsize - 1); i++) {
		if (dst[i] == '\0')
			break;
	}

	/* append the source string to the destination string */
	for (j = 0; i < (dstsize - 1); i++) {
		if (src[j] == '\0')
			break;

		dst[i] = src[j];
		j++;
	}

	/* set end of dst string to \0 */
	dst[i] = '\0';
	i++;

	return (i);
}

#endif /* !sun */
