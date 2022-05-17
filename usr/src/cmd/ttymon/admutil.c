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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
#include "tmstruct.h"
#include "ttymon.h"

/*
 *	find_label - return 1 if ttylabel already exists
 *		   - return 0 otherwise
 */
int
find_label(FILE *fp, char *ttylabel)
{
	char *p;		/* working pointer */
	int line = 0;		/* line number we found entry on */
	static char buf[BUFSIZ]; /* scratch buffer */

	while (fgets(buf, BUFSIZ, fp)) {
		line++;
		p = buf;
		while (isspace(*p))
			p++;
		if ((p = strtok(p, " :")) != NULL) {
			if (strcmp(p, ttylabel) == 0)
				return (line);
		}
	}
	if (!feof(fp)) {
		(void) fprintf(stderr, "error reading \"%s\"\n", TTYDEFS);
		return (0);
	}
	return (0);
}
