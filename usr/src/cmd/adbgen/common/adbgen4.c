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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Post-process adb scripts to move increment and decrement around.
 * The reason is that at the start of each +/ line, adb prints out
 * the current location.  If the line then increments or decrements
 * dot before printing the user may be confused.  So we move the
 * increment or decrement to the preceeding line.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define	BUFSIZE 1024	/* gross enough to never be exceeded (we hope) */

char buf1[BUFSIZE], buf2[BUFSIZE];

static char *scanpastnum(char *);
static int goodstart(char *);

int
main()
{
	char *cur, *last, *cp1, *cp2, *ep, *t;
	int len;

	gets(buf1);
	last = buf1;
	cur = buf2;
	while (gets(cur) != NULL) {
		if (goodstart(cur) && goodstart(last)) {
			/*
			 * Scan cur for initial increment.
			 * Ignore quoted strings, tabbing, adb newlines.
			 */
			cp1 = cur + 2;
			while (*cp1) {
				if (*cp1 == '"') {
					/* scan past quoted string */
					while (*++cp1 && *cp1 != '"')
						;
					cp1++;
					continue;
				}
				if (*cp1 >= '0' && *cp1 <= '9') {
					cp2 = scanpastnum(cp1);
				} else {
					cp2 = cp1;
				}
				if (*cp2 == 't' || *cp2 == 'n' ||
				    *cp2 == ' ') {
					/* ok to skip over this one */
					cp1 = cp2 + 1;
					continue;
				} else {
					break;
				}
			}
			/*
			 * Cp1 now points at the first non-quoted string and
			 * non adb tab specification.
			 * Now determine if it's an increment or decrement.
			 */
			cp2 = scanpastnum(cp1);
			if (*cp2 == '+' || *cp2 == '-') {
				/*
				 * This is what we were hoping to find.
				 * Move increment or decrement into last.
				 */
				cp2++;
				ep = last + strlen(last);
				len = cp2  - cp1;
				strncpy(ep, cp1, len);
				ep[len] = '\0';
				/*
				 * Remove it from cur.
				 */
				strcpy(cp1, cp2);
			}
		}
		/*
		 * Prepare for next iteration.
		 */
		puts(last);
		t = cur;
		cur = last;
		last = t;
	}
	puts(last);
	return (0);
}

/*
 * Cp points at a digit.
 * Return pointer to next char that isn't a digit.
 */
static char *
scanpastnum(char *cp1)
{
	char *cp2;

	for (cp2 = cp1; isdigit(*cp2); cp2++)
		;
	return (cp2);
}

/*
 * Check whether a line has a good starting string.
 * We need ./ or +/ at the beginning to even think
 * of doing this motion stuff.
 */
static int
goodstart(char *cp)
{
	if (*cp == '.' || *cp == '+') {
		if (*++cp == '/')
			return (1);
	}
	return (0);
}
