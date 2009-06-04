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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

char *
srcpath(char *dir, char *src, int part, int nparts)
{
	static char tmppath[PATH_MAX];
	char	*copy;
	size_t	copyLen;

	copy = tmppath;

	if (dir != NULL) {
		size_t theLen = strlen(dir);

		(void) strcpy(copy, dir);
		copy += theLen;
		copyLen = (sizeof (tmppath) - theLen);
	} else {
		copy[0] = '\0';
		copyLen = sizeof (tmppath);
	}

	if (nparts > 1) {
		(void) snprintf(copy, copyLen,
			((src[0] == '/') ? "/root.%d%s" : "/reloc.%d/%s"),
			part, src);
	} else {
		(void) snprintf(copy, copyLen,
			((src[0] == '/') ? "/root%s" : "/reloc/%s"), src);
	}

	return (tmppath);
}
