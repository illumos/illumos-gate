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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

/*
 * Takes a (10 char) permission string (as returned by ls -l) and prints
 * the equivalent octal number.
 * E.g. -rwsr-xr-- => 04754
 */

int
main(int argc, char **argv)
{
	char *perm;
	int result = 0;

	if ((argc != 2) || (strlen(argv[1]) != 10)) {
		printf("-1\n");
		return (1);
	}

	perm = argv[1];

	/* user bits */
	if (perm[1] == 'r')
		result = result | 00400;
	if (perm[2] == 'w')
		result = result | 00200;
	if (perm[3] == 'x')
		result = result | 00100;
	else if (perm[3] == 's')
		result = result | 04100;
	else if (perm[3] == 'S')
		result = result | 04000;

	/* group bits */
	if (perm[4] == 'r')
		result = result | 00040;
	if (perm[5] == 'w')
		result = result | 00020;
	if (perm[6] == 'x')
		result = result | 00010;
	else if (perm[6] == 's')
		result = result | 02010;
	else if (perm[6] == 'S')
		result = result | 02000;

	/* world bits */
	if (perm[7] == 'r')
		result = result | 00004;
	if (perm[8] == 'w')
		result = result | 00002;
	if (perm[9] == 'x')
		result = result | 00001;
	else if (perm[9] == 't')
		result = result | 01001;
	else if (perm[9] == 'T')
		result = result | 01000;

	printf("%05o\n", result);
	return (0);
}
