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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * For now, just two routines: one to allocate a string in shared
 * memory, and one to get the final file or directory name from a
 * supplied pathname.
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
