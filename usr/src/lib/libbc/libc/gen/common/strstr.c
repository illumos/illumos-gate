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
 * Get matching substring
 */
#include <string.h>

#pragma weak strstr = _strstr

char *
_strstr(s1, s2)
	register char *s1, *s2;
{
	int s2len = strlen(s2);	/* length of the second string */
	/*
	 * If the length of the second string is 0, 
	 *  return the first argument.
	 */
	if (s2len == 0)
		return (s1);

	while (strlen(s1) >= s2len) { 
		if (strncmp(s1, s2, s2len) == 0)
			return (s1);
		s1++;
	}
	return (0);
}
