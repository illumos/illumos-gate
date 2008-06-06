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
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * getsubopt - parse suboptions from a flag argument.
 */
#pragma weak _getsubopt = getsubopt

#include "lint.h"
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int
getsubopt(char **optionsp, char * const *tokens, char **valuep)
{
	char *s = *optionsp, *p;
	int i;
	size_t optlen;

	*valuep = NULL;
	if (*s == '\0')
		return (-1);
	p = strchr(s, ',');		/* find next option */
	if (p == NULL) {
		p = s + strlen(s);
	} else {
		*p++ = '\0';		/* mark end and point to next */
	}
	*optionsp = p;			/* point to next option */
	p = strchr(s, '=');		/* find value */
	if (p == NULL) {
		optlen = strlen(s);
		*valuep = NULL;
	} else {
		optlen = p - s;
		*valuep = ++p;
	}
	for (i = 0; tokens[i] != NULL; i++) {
		if ((optlen == strlen(tokens[i])) &&
		    (strncmp(s, tokens[i], optlen) == 0))
			return (i);
	}
	/* no match, point value at option and return error */
	*valuep = s;
	return (-1);
}
