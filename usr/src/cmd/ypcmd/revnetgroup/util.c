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
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SMI4.1 1.4 */

#include <stdio.h>
#include <string.h>
#include "util.h"




/*
 * This is just like fgets, but recognizes that "\\n" signals a continuation
 * of a line
 */
char *
getline(line, maxlen, fp)
	char *line;
	int maxlen;
	FILE *fp;
{
	register char *p;
	register char *start;
	int c;

	start = line;

nextline:
	if (fgets(start, maxlen, fp) == NULL) {
		return (NULL);
	}
	for (p = start; *p; p++) {
		if (*p == '\n') {
			if (p > start && *(p-1) == '\\') {
				start = p - 1;
				maxlen++;
				goto nextline;
			} else {
				return (line);
			}
		}
		maxlen--;
	}

	/*
	 * Input line is too long. Rest of the line needs to be discarded.
	 * Reinsert the last char into the stream. This is done so that
	 * in case the last char read is '\' and it is followed by a '\n'
	 * then the next line too can be discarded.
	 */
	if (p > start)
		(void) ungetc(*(p-1), fp);

	/*
	 * Discard the rest of the line
	 */
	while ((c = getc(fp)) != EOF) {
		if (c == '\n')
			break;
		else if (c == '\\') {
			/*
			 * Ignore the next character except EOF
			 */
			if (getc(fp) == EOF)
				break;
		}
	}

	maxlen = strlen(line) + 1;

	/*
	 * Certain functions expects a newline in the buffer.
	 */
	if (maxlen >= 2)
		line[maxlen - 2] = '\n';
	(void) fprintf(stderr, "Following line too long - remaining chars "
			"ignored\n--- %s", line);
	return (line);
}


void
fatal(message)
	char *message;
{
	(void) fprintf(stderr, "fatal error: %s\n", message);
	exit(1);
}
