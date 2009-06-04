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

extern char *root, *basedir; 		/* WHERE? */

void
cvtpath(char *path, char *copy)
{
	*copy++ = '/';
	if (root || (basedir && (*path != '/'))) {
		if (root && ((basedir == NULL) || (path[0] == '/') ||
		    (basedir[0] != '/'))) {
			/* look in root */
			(void) strcpy(copy, root + (*root == '/' ? 1 : 0));
			copy += strlen(copy);
			if (copy[-1] != '/')
				*copy++ = '/';
		}
		if (basedir && (*path != '/')) {
			(void) strcpy(copy,
			    basedir + (*basedir == '/' ? 1 : 0));
			copy += strlen(copy);
			if (copy[-1] != '/')
				*copy++ = '/';
		}
	}
	(void) strcpy(copy, path + (*path == '/' ? 1 : 0));
}
