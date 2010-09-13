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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <string.h>

#define	isdot(x)	((x[0] == '.') && (!x[1] || (x[1] == '/')))
#define	isdotdot(x)	((x[0] == '.') && (x[1] == '.') && \
			    (!x[2] || (x[2] == '/')))

void
canonize(char *file)
{
	char *pt, *last;
	int level;

	/* remove references such as "./" and "../" and "//" */
	for (pt = file; *pt; /* void */) {
		if (isdot(pt))
			(void) strcpy(pt, pt[1] ? pt+2 : pt+1);
		else if (isdotdot(pt)) {
			level = 0;
			last = pt;
			do {
				level++;
				last += 2;
				if (*last)
					last++;
			} while (isdotdot(last));
			--pt; /* point to previous '/' */
			while (level--) {
				if (pt <= file)
					return;
				while ((*--pt != '/') && (pt > file))
					;
			}
			if (*pt == '/')
				pt++;
			(void) strcpy(pt, last);
		} else {
			while (*pt && (*pt != '/'))
				pt++;
			if (*pt == '/') {
				while (pt[1] == '/')
					(void) strcpy(pt, pt+1);
				pt++;
			}
		}
	}
	if ((--pt > file) && (*pt == '/'))
		*pt = '\0';
}

void
canonize_slashes(char *file)
{
	char *pt;

	/* remove references such as "//" */
	for (pt = file; *pt; /* void */) {
		while (*pt && (*pt != '/'))
			pt++;
		if (*pt == '/') {
			while (pt[1] == '/')
				(void) strcpy(pt, pt+1);
			pt++;
		}
	}
	if ((--pt > file) && (*pt == '/'))
		*pt = '\0';
}
