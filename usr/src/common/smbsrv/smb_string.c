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

/*
 * Implementation of some of the string functions.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#endif
#include <smbsrv/alloc.h>
#include <smbsrv/string.h>
#include <smbsrv/ctype.h>


/*
 * strsubst
 *
 * Scan a string replacing all occurrences of orgchar with newchar.
 * Returns a pointer to s, or null of s is null.
 */
char *
strsubst(char *s, char orgchar, char newchar)
{
	char *p = s;

	if (p == 0)
		return (0);

	while (*p) {
		if (*p == orgchar)
			*p = newchar;
		++p;
	}

	return (s);
}

/*
 * strcanon
 *
 * Normalize a string by reducing all the repeated characters in
 * buf as defined by class. For example;
 *
 *		char *buf = strdup("/d1//d2//d3\\\\d4\\\\f1.txt");
 *		strcanon(buf, "/\\");
 *
 * Would result in buf containing the following string:
 *
 *		/d1/d2/d3\d4\f1.txt
 *
 * This function modifies the contents of buf in place and returns
 * a pointer to buf.
 */
char *
strcanon(char *buf, const char *class)
{
	char *p = buf;
	char *q = buf;
	char *r;

	while (*p) {
		*q++ = *p;

		if ((r = strchr(class, *p)) != 0) {
			while (*p == *r)
				++p;
		} else
			++p;
	}

	*q = '\0';
	return (buf);
}
