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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SMI4.1 1.3 */

#include <stdio.h>
#include <string.h>

#define	iseol(c)	(c == 0 || c == '\n' || strchr(com, c) != NULL)
#define	issep(c)	(strchr(sep, c) != NULL)
#define	isignore(c)	(strchr(ignore, c) != NULL)

/*
 * getline()
 * Read a line from a file.
 * What's returned is a cookie to be passed to getname
 */
char **
getline(line, maxlinelen, f, lcount, com)
	char *line;
	int maxlinelen;
	FILE *f;
	int *lcount;
	char *com;
{
	char *p;
	static char *lp;
	do {
		if (! fgets(line, maxlinelen, f)) {
			return (NULL);
		}
		(*lcount)++;
	} while (iseol(line[0]));
	p = line;
	for (;;) {
		while (*p) {
			p++;
		}
		if (*--p == '\n' && *--p == '\\') {
			if (! fgets(p, maxlinelen, f)) {
				break;
			}
			(*lcount)++;
		} else {
			break;
		}
	}
	lp = line;
	return (&lp);
}


/*
 * getname()
 * Get the next entry from the line.
 * You tell getname() which characters to ignore before storing them
 * into name, and which characters separate entries in a line.
 * The cookie is updated appropriately.
 * return:
 *	  1: one entry parsed
 *	  0: partial entry parsed, ran out of space in name
 *  -1: no more entries in line
 */
int
getname(name, namelen, ignore, sep, linep, com)
	char *name;
	int namelen;
	char *ignore;
	char *sep;
	char **linep;
	char *com;
{
	register char c;
	register char *lp;
	register char *np;

	lp = *linep;
	do {
		c = *lp++;
	} while (isignore(c) && !iseol(c));
	if (iseol(c)) {
		*linep = lp - 1;
		return (-1);
	}
	np = name;
	while (! issep(c) && ! iseol(c) && np - name < namelen) {
		*np++ = c;
		c = *lp++;
	}
	lp--;
	if (np - name < namelen) {
		*np = 0;
		if (iseol(c)) {
			*lp = 0;
		} else {
			lp++; 	/* advance over separator */
		}
	} else {
		*linep = lp;
		return (0);
	}
	*linep = lp;
	return (1);
}
