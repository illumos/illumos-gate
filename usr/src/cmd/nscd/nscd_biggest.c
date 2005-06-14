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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * routines to find largest n numbers, carrying 4 bytes of data
 */

int *
maken(int n)
{
	int * ret;

	n++;

	ret = (int *) memset(malloc(2 * n *sizeof (int)),
	    -1, 2 * n * sizeof (int));
	ret[0] = n - 1;
	return (ret);
}

insertn(int * table, int n, int data)
{
	int size = *table;
	int guess, base, last;
	int olddata;

	if (table[1] > n)
		return (data);

	if (table[size] < n)  /* biggest so far */
		guess = size;
	else {
		base = 1;
		last = size;
		while (last >= base) {
			guess = (last+base)/2;
			if (table[guess] == n)
				goto doit;
			if (table[guess] > n)
				last = guess -1;
			else
				base = guess + 1;
		}
		guess = last;
	}
	doit:
	olddata = table[2 + size];
	memmove(table + 1, table+2, sizeof (int) * (guess-1));
	memmove(table + 2 + size, table + 3 + size, sizeof (int) * (guess-1));
	table[guess + size + 1] = data;
	table[guess] = n;
	return (olddata);
}

/*
 *  test code
 */
#if 0
int
main(int argc, char * argv[])
{
	int * t;
	char buffer[100];
	int i, n;
	char * tmp;

	t = maken(100);

	for (i = 0; i < 1100; i++) {
		n = random();
		sprintf(buffer, "trial %d: %d", i, n);
		tmp = (char *)insertn(t, n, (int)strdup(buffer));
		if (tmp != -1) {
			printf("freeing %s\n", tmp);
			free(tmp);
		}
	}

	for (i = 1; i <= 100; i++) {
		printf("%d: %s\n", i, t[100 + 1 + i]);
		free((char *)t[100 + 1 + i]);
	}

	free(t);
}
#endif
